#!/usr/bin/env bash
# Toggle_TOR — turn transparent Tor torification on/off and report status.
#
#   toggle_tor.sh on  [--no-deadman] [--deadman N]   enable + persist the kill-switch
#   toggle_tor.sh off                                  disable + un-persist (survives reboot)
#   toggle_tor.sh status                               show current state + exit IP
#
# "on"  : ensures tor is up + bootstrapped, then loads the nftables kill-switch (all outbound
#         TCP -> Tor; LAN/loopback/tor-uid/NTP exempt) and enables it at boot. On a live/remote
#         host it arms a systemd-timer DEAD-MAN that auto-reverts in N seconds (default 240)
#         unless verification (a plain curl returns a Tor exit IP) passes first.
# "off" : stops + disables the kill-switch so outbound flows normally (DNS still encrypted via
#         dnscrypt, egress still blocks plaintext 80/53). tor.service is left running for opt-in
#         SOCKS on 127.0.0.1:9050; pass --stop-tor to also stop it.
set -uo pipefail
SVC=secbase-tor-killswitch.service
TABLE='inet secbase_tor'
RULE=/etc/nftables/secbase-tor.nft
ACT="${1:-status}"; shift || true
DEADMAN=240; STOP_TOR=0
for a in "$@"; do case "$a" in --no-deadman) DEADMAN=0;; --deadman) shift; DEADMAN="${1:-240}";; --deadman=*) DEADMAN="${a#*=}";; --stop-tor) STOP_TOR=1;; esac; done
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

has_table(){ nft list table $TABLE >/dev/null 2>&1; }
exit_ip(){ curl -s --max-time 25 https://api.ipify.org 2>/dev/null; }
boot_tor(){
  systemctl is-active tor >/dev/null 2>&1 || systemctl start tor
  for i in $(seq 1 20); do
    journalctl -u tor --no-pager 2>/dev/null | grep -q 'Bootstrapped 100%' && return 0; sleep 3
  done; return 0; }

case "$ACT" in
  on)
    has_table && { echo "already ON"; exit 0; }
    echo "[*] ensuring tor is bootstrapped..."; boot_tor
    if [ "$DEADMAN" -gt 0 ]; then
      systemctl stop tor-killswitch-deadman.timer 2>/dev/null
      systemd-run --on-active="$DEADMAN" --unit=tor-killswitch-deadman --timer-property=AccuracySec=1s \
        /bin/bash -c "systemctl stop $SVC; nft delete table $TABLE 2>/dev/null" >/dev/null 2>&1 \
        && echo "[*] dead-man armed: auto-OFF in ${DEADMAN}s unless verification passes"
    fi
    echo "[*] applying kill-switch..."; systemctl enable "$SVC" >/dev/null 2>&1; systemctl start "$SVC"
    has_table || { echo "[x] failed to load ruleset"; exit 1; }
    echo "[*] verifying transparent exit..."; ip=$(exit_ip)
    if [ -n "$ip" ]; then
      echo "[+] ON — outbound exits via Tor: $ip"
      [ "$DEADMAN" -gt 0 ] && { systemctl stop tor-killswitch-deadman.timer 2>/dev/null; echo "[*] dead-man cancelled"; }
    else
      echo "[!] no exit IP returned; leaving dead-man to auto-revert (or run: $0 off)"
    fi
    ;;
  off)
    systemctl stop tor-killswitch-deadman.timer 2>/dev/null
    systemctl disable "$SVC" >/dev/null 2>&1; systemctl stop "$SVC" 2>/dev/null
    nft delete table $TABLE 2>/dev/null
    has_table && echo "[x] still ON?!" || echo "[+] OFF — normal outbound restored (DNS still encrypted; plaintext 80/53 still blocked)"
    [ "$STOP_TOR" = 1 ] && { systemctl stop tor; echo "[*] tor.service stopped"; }
    ;;
  status)
    if has_table; then echo "kill-switch: ON"; echo "exit IP:    $(exit_ip)"; else echo "kill-switch: OFF"; fi
    echo "tor.service: $(systemctl is-active tor 2>/dev/null) ($(systemctl is-enabled tor 2>/dev/null))"
    echo "persist@boot: $(systemctl is-enabled $SVC 2>/dev/null)"
    ;;
  *) echo "usage: $0 {on|off|status} [--no-deadman] [--deadman N] [--stop-tor]" >&2; exit 2;;
esac
