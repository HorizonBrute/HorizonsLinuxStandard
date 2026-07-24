#!/usr/bin/env bash
# netmode — switch the system's default egress anonymity backend.
#
#   netmode status                         show active mode, wg wrap, exit IP
#   netmode tor      [--wg|--no-wg]        transparent Tor kill-switch (all TCP -> 9040)
#   netmode lokinet  [--wg|--no-wg]        transparent Lokinet L3 tun kill-switch
#   netmode nym      [--wg|--no-wg]        Nym mixnet via redsocks -> SOCKS5 (fail-closed)
#   netmode raw      [--wg|--no-wg]        no anonymizer (direct; plaintext 80/53 still blocked)
#   netmode wg on|off [--conf NAME]        toggle WireGuard outer wrap without changing mode
#   netmode provision {lokinet|nym|wireguard}   install/prepare a backend
#   netmode --apply-boot                   internal: re-apply persisted state at boot
#
# Model: exactly ONE egress mode is active, enforced by a single nftables table
# `inet secbase_net` (fail-closed: anything the backend can't carry is dropped).
# LAN, loopback, the backend's own uplink, and NTP are always exempt, so LAN SSH
# (management plane) never drops even when clearnet egress is down.
#
# WireGuard "wrap" (--wg) is orthogonal to the mode: it routes the *anonymizer's
# uplink* out an external wg interface (VPN-under-anonymizer chain). If wg is down
# the marked uplink has no route -> dropped (fail-closed).
set -uo pipefail

TABLE='inet secbase_net'
NFT=/etc/nftables/secbase-net.nft
STATE=/etc/secbase/netmode.conf
BOOTSVC=secbase-netmode.service
LEGACY_TOR_SVC=secbase-tor-killswitch.service
REDSOCKS_NYM=/etc/redsocks-nym.conf
WGMARK=0x1
WGTABLE=51

# --- backend fixed params ---
TOR_TRANSPORT=9040
TOR_UID=966
NYM_SOCKS=127.0.0.1:1080
REDSOCKS_PORT=9042
LOKI_TUN=lokitun0

LAN4='{ 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255 }'
LAN6='{ ::1, fc00::/7, fe80::/10, ff00::/8 }'

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
mkdir -p /etc/secbase

# ---------- helpers ----------
say(){ echo "[*] $*"; }
ok(){ echo "[+] $*"; }
err(){ echo "[x] $*" >&2; }
has_table(){ nft list table $TABLE >/dev/null 2>&1; }
uid_of(){ id -u "$1" 2>/dev/null; }        # returns "" if user missing
loki_uid(){ uid_of lokinet || uid_of _lokinet; }
nym_uid(){ uid_of nym; }
exit_ip(){ curl -s --max-time 30 https://api.ipify.org 2>/dev/null; }

load_state(){ MODE=raw; WG=off; WG_CONF=""; [ -f "$STATE" ] && . "$STATE"; }
save_state(){ printf 'MODE=%s\nWG=%s\nWG_CONF=%s\n' "$MODE" "$WG" "$WG_CONF" > "$STATE"; }

backend_ready(){ # verify a backend is provisioned+runnable before we switch to it
  case "$1" in
    tor)     command -v tor >/dev/null && return 0 ;;
    lokinet) command -v lokinet >/dev/null && [ -n "$(loki_uid)" ] && return 0 ;;
    nym)     command -v nym-socks5-client >/dev/null && command -v redsocks >/dev/null && [ -n "$(nym_uid)" ] && return 0 ;;
    raw)     return 0 ;;
  esac; return 1; }

# ---------- WireGuard wrap ----------
wg_iface(){ [ -n "${WG_CONF:-}" ] && echo "$WG_CONF"; }
wg_up(){
  local c; c="$(wg_iface)"; [ -n "$c" ] || { err "no wg conf set (--conf NAME, needs /etc/wireguard/NAME.conf)"; return 1; }
  [ -f "/etc/wireguard/$c.conf" ] || { err "/etc/wireguard/$c.conf missing"; return 1; }
  command -v wg-quick >/dev/null || { err "wireguard-tools not installed (netmode provision wireguard)"; return 1; }
  ip link show "$c" >/dev/null 2>&1 || wg-quick up "$c" >/dev/null 2>&1
  ip link show "$c" >/dev/null 2>&1 || { err "wg iface $c failed to come up"; return 1; }
  # own the routing: send only marked (anonymizer uplink) traffic via wg, not the whole box
  ip route replace default dev "$c" table "$WGTABLE" 2>/dev/null
  ip rule add fwmark "$WGMARK" lookup "$WGTABLE" 2>/dev/null || true
  ok "wg wrap up ($c)"; }
wg_down(){
  local c; c="$(wg_iface)"
  ip rule del fwmark "$WGMARK" lookup "$WGTABLE" 2>/dev/null || true
  ip route flush table "$WGTABLE" 2>/dev/null || true
  [ -n "$c" ] && ip link show "$c" >/dev/null 2>&1 && wg-quick down "$c" >/dev/null 2>&1
  return 0; }

# nft snippet: mark the backend uplink so wg routing catches it (only when WG=on)
wg_mark_rule(){ [ "$WG" = on ] && echo "meta skuid $1 meta mark set $WGMARK"; }

# ---------- nftables rulesets (single table, regenerated per switch) ----------
gen_nft(){
  local mode="$1" uplink_uid="$2" markline; markline="$(wg_mark_rule "$uplink_uid")"
  case "$mode" in
    tor|nym)
      # redirect model: all outbound TCP -> local transparent shim; drop UDP/ICMP.
      local port; [ "$mode" = tor ] && port=$TOR_TRANSPORT || port=$REDSOCKS_PORT
      cat > "$NFT" <<EOF
table $TABLE {
  chain output_nat {
    type nat hook output priority dstnat; policy accept;
    oifname "lo" return
    meta skuid $uplink_uid return
    ip daddr $LAN4 return
    ip6 daddr $LAN6 return
    meta l4proto tcp redirect to :$port
  }
  chain output_filter {
    type filter hook output priority filter; policy accept;
    oifname "lo" accept
    ${markline:+$markline}
    meta skuid $uplink_uid accept
    ct state established,related accept
    ip daddr $LAN4 accept
    ip6 daddr $LAN6 accept
    udp dport 123 accept
    meta l4proto udp drop
    meta l4proto { icmp, ipv6-icmp } drop
  }
}
EOF
      ;;
    lokinet)
      # tun model: everything routes into the tun; drop anything that would leave a
      # physical NIC. lo, tun, lokinet uplink, LAN and NTP are exempt (fail-closed).
      cat > "$NFT" <<EOF
table $TABLE {
  chain output_filter {
    type filter hook output priority filter; policy accept;
    oifname "lo" accept
    oifname "$LOKI_TUN" accept
    ${markline:+$markline}
    meta skuid $uplink_uid accept
    ct state established,related accept
    ip daddr $LAN4 accept
    ip6 daddr $LAN6 accept
    udp dport 123 accept
    meta l4proto { icmp, ipv6-icmp } drop
    drop
  }
}
EOF
      ;;
  esac
}

apply_table(){ nft -c -f "$NFT" 2>/tmp/netmode.nfterr || { err "nft validation failed:"; cat /tmp/netmode.nfterr >&2; return 1; }
  nft delete table $TABLE 2>/dev/null; nft -f "$NFT"; }

teardown_table(){ nft delete table $TABLE 2>/dev/null; rm -f "$NFT"; }

# ---------- backend lifecycle ----------
backend_start(){
  case "$1" in
    tor)     systemctl is-active tor >/dev/null 2>&1 || systemctl start tor
             for i in $(seq 1 20); do journalctl -u tor --no-pager 2>/dev/null | grep -q 'Bootstrapped 100%' && break; sleep 3; done ;;
    lokinet) systemctl start lokinet ; sleep 3 ; ip link show "$LOKI_TUN" >/dev/null 2>&1 || { err "$LOKI_TUN not up"; return 1; } ;;
    nym)     systemctl start nym-socks5 2>/dev/null || systemctl start nym-socks5-client 2>/dev/null
             gen_redsocks; systemctl restart redsocks-nym 2>/dev/null || redsocks -c "$REDSOCKS_NYM" >/dev/null 2>&1 & sleep 2 ;;
  esac; }
backend_stop_others(){ # stop backends that aren't the target (leave tor running for opt-in SOCKS)
  local keep="$1"
  [ "$keep" != lokinet ] && systemctl stop lokinet 2>/dev/null
  [ "$keep" != nym ] && { systemctl stop nym-socks5 nym-socks5-client redsocks-nym 2>/dev/null; pkill -f "redsocks -c $REDSOCKS_NYM" 2>/dev/null; }
  return 0; }

gen_redsocks(){ cat > "$REDSOCKS_NYM" <<EOF
base { log_debug = off; log_info = on; daemon = on; redirector = nftables; }
redsocks { local_ip = 127.0.0.1; local_port = $REDSOCKS_PORT; ip = ${NYM_SOCKS%:*}; port = ${NYM_SOCKS#*:}; type = socks5; }
EOF
}

# ---------- switch ----------
switch(){
  local mode="$1"
  backend_ready "$mode" || { err "backend '$mode' not provisioned. run: netmode provision $mode"; exit 1; }
  # resolve uplink uid for exemption/marking
  local uid=0
  case "$mode" in tor) uid=$TOR_UID;; lokinet) uid="$(loki_uid)";; nym) uid="$(nym_uid)";; raw) uid=0;; esac

  say "switching -> $mode (wg=$WG)"
  teardown_table
  [ "$WG" = on ] && wg_up || wg_down
  backend_stop_others "$mode"

  if [ "$mode" = raw ]; then
    # retire BOTH the netmode table and the legacy standalone tor kill-switch
    systemctl -q disable "$LEGACY_TOR_SVC" 2>/dev/null; systemctl stop "$LEGACY_TOR_SVC" 2>/dev/null
    nft delete table inet secbase_tor 2>/dev/null
    systemctl -q disable "$BOOTSVC" 2>/dev/null
    ok "raw — direct egress (plaintext 80/53 still blocked; DNS still encrypted via dnscrypt)"
    MODE=raw; WG=off; save_state; return 0
  fi

  backend_start "$mode" || { err "backend failed to start; staying fail-closed torn down"; exit 1; }
  gen_nft "$mode" "$uid"
  apply_table || { err "kill-switch apply failed"; exit 1; }
  has_table || { err "table not loaded"; exit 1; }
  MODE="$mode"; save_state
  systemctl enable "$BOOTSVC" >/dev/null 2>&1
  systemctl -q disable "$LEGACY_TOR_SVC" 2>/dev/null; nft delete table inet secbase_tor 2>/dev/null

  say "verifying exit..."; local ip; ip="$(exit_ip)"
  if [ -n "$ip" ]; then ok "$mode ACTIVE — exit IP: $ip"
  else err "no exit IP returned. Kill-switch is UP and fail-closed (traffic dropped). Fix the backend or: netmode raw"; fi
}

# ---------- provisioning ----------
provision(){
  case "$1" in
    wireguard) dnf install -y wireguard-tools && ok "wireguard-tools installed. Drop a provider conf at /etc/wireguard/NAME.conf, then: netmode wg on --conf NAME" ;;
    nym)       dnf install -y redsocks
               id nym >/dev/null 2>&1 || useradd -r -s /sbin/nologin -d /var/lib/nym nym
               echo "redsocks installed + 'nym' user ready."
               echo "Install the nym-socks5-client binary (GitHub release or cargo) as a systemd service"
               echo "named nym-socks5 running as user 'nym', SOCKS5 on $NYM_SOCKS, then: netmode nym" ;;
    lokinet)   echo "Lokinet has no Fedora package. Provision via upstream:"
               echo "  1. add Oxen RPM repo / install lokinet release, enable lokinet.service"
               echo "  2. set an exit node in /etc/loki/lokinet/lokinet.ini (e.g. exit-node=...)"
               echo "  3. confirm 'lokinet' user + $LOKI_TUN exist, then: netmode lokinet" ;;
    *) err "unknown backend: $1"; exit 2;;
  esac; }

# ---------- status ----------
status(){
  load_state
  echo "mode:        $MODE"
  echo "kill-switch: $(has_table && echo "UP ($TABLE)" || echo "down")"
  echo "wg wrap:     $WG${WG_CONF:+ ($WG_CONF)}$([ "$WG" = on ] && { ip link show "$WG_CONF" >/dev/null 2>&1 && echo " [iface up]" || echo " [iface DOWN]"; })"
  echo "backends:    tor=$(systemctl is-active tor 2>/dev/null) lokinet=$(systemctl is-active lokinet 2>/dev/null) nym=$(systemctl is-active nym-socks5 2>/dev/null)"
  echo "persist:     $(systemctl is-enabled $BOOTSVC 2>/dev/null)"
  [ "$MODE" != raw ] && echo "exit IP:     $(exit_ip)"
  return 0; }

# ---------- arg parse ----------
load_state
ACT="${1:-status}"; shift || true
REQ_WG="$WG"   # default: keep current wrap
for a in "$@"; do case "$a" in
  --wg) REQ_WG=on;; --no-wg) REQ_WG=off;;
  --conf) shift; WG_CONF="${1:-}";; --conf=*) WG_CONF="${a#*=}";;
esac; done
WG="$REQ_WG"

case "$ACT" in
  status) status ;;
  tor|lokinet|nym|raw) switch "$ACT" ;;
  wg) sub="${1:-}"; case "$sub" in
        on)  WG=on; [ -n "$WG_CONF" ] || { err "--conf NAME required"; exit 2; }; wg_up && { save_state; switch "$MODE"; } ;;
        off) WG=off; wg_down; save_state; switch "$MODE" ;;
        *) err "usage: netmode wg {on|off} [--conf NAME]"; exit 2;; esac ;;
  provision) provision "${1:-}" ;;
  --apply-boot) [ "$MODE" != raw ] && { [ "$WG" = on ] && wg_up; switch "$MODE"; } ;;
  *) echo "usage: netmode {status|tor|lokinet|nym|raw|wg on|off|provision <backend>} [--wg|--no-wg] [--conf NAME]" >&2; exit 2;;
esac
