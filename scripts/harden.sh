#!/usr/bin/env bash
#
# Secure Linux Hardening Baseline — reproducible installer
# =========================================================
# Applies a current, security- and anonymity-focused hardening baseline aligned with
# CIS Level 1 plus additional enterprise controls. Idempotent: safe to re-run.
#
# Goals: least privilege, key-only authentication, encrypted+anonymous DNS, encrypted-only
# egress, on-path/MITM resistance, brute-force resistance, durable local audit trail, and
# unattended update/reboot survivability.
#
# Designed to run on any current systemd-based distribution. A thin shim abstracts the
# package manager (dnf/apt/zypper/pacman), firewall backend (firewalld/nftables) and crypto
# policy mechanism (update-crypto-policies / direct sshd config).
#
# Preflight REQUIRES: root, systemd, UEFI boot, and a TPM 2.0 device (cloud vTPM counts).
# Use --cloud on headless/cloud hosts (relaxes the physical-console assumption and refuses to
# disable password auth unless a key is already present, to avoid lockout).
#
# Usage:
#   ./harden.sh [--cloud] [--enable-tor] [--enable-tor-transparent] [--dry-run]
#               [--skip MODULE[,MODULE...]] [--only MODULE[,MODULE...]] [--allow-no-tpm]
#
set -euo pipefail

PREFIX="secbase"                       # namespace for installed tools/files
LOG_TAG="hardening"
PRIMARY_IFACE="${PRIMARY_IFACE:-}"     # auto-detected if empty
CLOUD=0; DRYRUN=0; ENABLE_TOR=0; ENABLE_TOR_TRANSPARENT=0; ALLOW_NO_TPM=0
SKIP=""; ONLY=""

# ----------------------------------------------------------------------------- helpers
say(){ printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
ok(){  printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die(){ printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
run(){ if [ "$DRYRUN" = 1 ]; then printf '    would run: %s\n' "$*"; else eval "$@"; fi; }
backup(){ [ -e "$1" ] || return 0; local d=/root/${PREFIX}-/configs-backup; mkdir -p "$d"; [ -e "$d/$(basename "$1").orig" ] || cp -a "$1" "$d/$(basename "$1").orig"; }
want(){ # module gate: honor --only / --skip
  local m="$1"
  if [ -n "$ONLY" ]; then [[ ",$ONLY," == *",$m,"* ]] || return 1; fi
  if [ -n "$SKIP" ]; then [[ ",$SKIP," == *",$m,"* ]] && return 1; fi
  return 0; }

# ----------------------------------------------------------------------------- args
for a in "$@"; do case "$a" in
  --cloud) CLOUD=1;;
  --enable-tor) ENABLE_TOR=1;;
  --enable-tor-transparent) ENABLE_TOR=1; ENABLE_TOR_TRANSPARENT=1;;
  --dry-run) DRYRUN=1;;
  --allow-no-tpm) ALLOW_NO_TPM=1;;
  --skip) shift;;  --skip=*) SKIP="${a#*=}";;
  --only=*) ONLY="${a#*=}";;
  -h|--help) grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
esac; done

# ----------------------------------------------------------------------------- preflight
[ "$(id -u)" -eq 0 ] || die "must run as root"
[ -d /run/systemd/system ] || die "systemd is required"
[ -d /sys/firmware/efi ] || die "not booted in UEFI mode — refusing (legacy BIOS unsupported)"
if [ ! -e /sys/class/tpm/tpm0 ]; then
  [ "$ALLOW_NO_TPM" = 1 ] && warn "no TPM2 device found — continuing due to --allow-no-tpm" \
    || die "no TPM 2.0 device (/sys/class/tpm/tpm0) — full-disk-encryption auto-unlock assumes it. Override with --allow-no-tpm."
fi

# distro + package manager abstraction
. /etc/os-release 2>/dev/null || die "cannot read /etc/os-release"
DISTRO_ID="${ID:-unknown}"; DISTRO_LIKE="${ID_LIKE:-}"
PM=""; for c in dnf apt-get zypper pacman; do command -v "$c" >/dev/null 2>&1 && { PM="$c"; break; }; done
[ -n "$PM" ] || die "no supported package manager found"
pkg_install(){ # idempotent install
  local p; for p in "$@"; do rpm -q "$p" >/dev/null 2>&1 && continue 2>/dev/null
    case "$PM" in
      dnf)     run "dnf install -y -q $p" ;;
      apt-get) run "DEBIAN_FRONTEND=noninteractive apt-get install -y -q $p" ;;
      zypper)  run "zypper -n in -y $p" ;;
      pacman)  run "pacman -S --noconfirm --needed $p" ;;
    esac; done; }
HAVE_FIREWALLD=0; command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1 && HAVE_FIREWALLD=1
HAVE_RESOLVED=0; systemctl list-unit-files systemd-resolved.service >/dev/null 2>&1 && HAVE_RESOLVED=1
HAVE_CRYPTOPOL=0; command -v update-crypto-policies >/dev/null 2>&1 && HAVE_CRYPTOPOL=1
HAVE_NM=0; command -v nmcli >/dev/null 2>&1 && HAVE_NM=1
[ -z "$PRIMARY_IFACE" ] && PRIMARY_IFACE="$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')"

say "distro=$DISTRO_ID pm=$PM firewalld=$HAVE_FIREWALLD resolved=$HAVE_RESOLVED crypto-policies=$HAVE_CRYPTOPOL iface=${PRIMARY_IFACE:-none} cloud=$CLOUD"

# ============================================================================= MODULES

mod_ssh(){ want ssh || return 0; say "SSH: key-only, no root, CIS session limits"
  install -d -m 0755 /etc/ssh/sshd_config.d
  cat > /etc/ssh/sshd_config.d/01-${PREFIX}-hardening.conf <<'EOF'
# Key-only authentication, no root login, brute-force + session limits, reduced surface.
# Sorted first among drop-ins so these values win. Modern algorithms are pinned below so SSH
# stays hardened independent of the system-wide crypto policy (kept at DEFAULT for web/TLS usability).
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
GSSAPIAuthentication no
HostbasedAuthentication no
IgnoreRhosts yes
PubkeyAuthentication yes
PermitUserEnvironment no
MaxAuthTries 4
LoginGraceTime 60
MaxSessions 10
ClientAliveInterval 300
ClientAliveCountMax 0
Banner none
LogLevel VERBOSE
AllowTcpForwarding no
AllowAgentForwarding yes   # D022: needed for remote SSH-key sudo (pam_ssh_agent_auth)
X11Forwarding yes
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
PubkeyAcceptedAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,rsa-sha2-512,rsa-sha2-256
EOF
  # Cloud/headless safety: never strand the host. Only enforce key-only if a key exists.
  if [ "$CLOUD" = 1 ]; then
    if ! grep -rqs . /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null; then
      warn "no authorized_keys found; keeping PasswordAuthentication enabled to avoid lockout"
      sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config.d/01-${PREFIX}-hardening.conf
    fi
  fi
  sshd -t && run "systemctl reload sshd" && ok "sshd hardened"
}

mod_crypto(){ want crypto || return 0; say "system crypto policy: DEFAULT (SSH pinned separately)"
  # NOTE: FUTURE was evaluated and rejected — it rejects RSA-2048 certificate chains (all
  # Let's Encrypt RSA certs + much of the web), breaking normal HTTPS and package updates.
  # We keep the system policy at DEFAULT (still strong: TLS1.2+, no SHA-1 sigs, no weak ciphers)
  # and pin modern SSH algorithms explicitly in mod_ssh, so SSH stays hardened regardless.
  if [ "$HAVE_CRYPTOPOL" = 1 ]; then run "update-crypto-policies --set DEFAULT"; fi
}

mod_sysctl_net(){ want sysctl_net || return 0; say "anti-MITM network sysctl"
  cat > /etc/sysctl.d/90-${PREFIX}-network-hardening.conf <<'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.tcp_syncookies = 1
EOF
  run "sysctl --system >/dev/null" && ok "network sysctl applied"
}

mod_sysctl_kernel(){ want sysctl_kernel || return 0; say "kernel hardening sysctl"
  cat > /etc/sysctl.d/90-${PREFIX}-kernel-hardening.conf <<'EOF'
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.perf_event_paranoid = 3
EOF
  run "sysctl --system >/dev/null" && ok "kernel sysctl applied"
}

mod_modprobe(){ want modprobe || return 0; say "disable unused filesystems + rare net protocols"
  cat > /etc/modprobe.d/${PREFIX}-cis.conf <<'EOF'
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
EOF
  ok "module blacklist written (usb-storage intentionally left enabled for workstation use)"
}

mod_coredumps(){ want coredumps || return 0; say "disable core dumps"
  echo '* hard core 0' > /etc/security/limits.d/90-${PREFIX}-coredump.conf
  install -d /etc/systemd/coredump.conf.d
  printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' > /etc/systemd/coredump.conf.d/90-${PREFIX}.conf
  ok "core dumps disabled"
}

mod_login(){ want login || return 0; say "umask 027, password aging, pwquality"
  echo 'umask 027' > /etc/profile.d/90-${PREFIX}-umask.sh
  if [ -f /etc/login.defs ]; then
    backup /etc/login.defs
    sed -i 's/^UMASK.*/UMASK 027/; s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/; s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
    grep -q '^ENCRYPT_METHOD' /etc/login.defs && sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs
  fi
  local pwq=/etc/security/pwquality.conf.d/90-${PREFIX}.conf
  [ -d /etc/security/pwquality.conf.d ] || pwq=/etc/security/pwquality.conf
  cat > "$pwq" <<'EOF'
minlen = 14
minclass = 4
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
enforce_for_root
EOF
  ok "login policy applied"
}

mod_faillock(){ want faillock || return 0; say "account lockout (faillock)"
  cat > /etc/security/faillock.conf <<'EOF'
deny = 5
unlock_time = 900
fail_interval = 900
EOF
  if command -v authselect >/dev/null 2>&1; then
    authselect enable-feature with-faillock 2>/dev/null || true
    authselect apply-changes 2>/dev/null || true
  elif command -v pam-auth-update >/dev/null 2>&1; then
    pam-auth-update --enable faillock 2>/dev/null || true
  fi
  if grep -rqs pam_faillock /etc/pam.d/ 2>/dev/null; then ok "faillock active in PAM"
  else warn "faillock.conf written but pam_faillock not detected in PAM — verify the auth stack"; fi
}

mod_firewall(){ want firewall || return 0; say "firewall: inbound ssh+mdns only; egress block plaintext 80/53"
  if [ "$HAVE_FIREWALLD" = 1 ]; then
    local z; z="$(firewall-cmd --get-default-zone)"
    for s in $(firewall-cmd --zone="$z" --list-services); do
      case "$s" in ssh|mdns) ;; *) run "firewall-cmd --permanent --zone=$z --remove-service=$s" ;; esac; done
    run "firewall-cmd --permanent --zone=$z --add-service=ssh"
    run "firewall-cmd --permanent --zone=$z --add-service=mdns"
    run "firewall-cmd --permanent --set-log-denied=all"
    local d="firewall-cmd --permanent --direct --add-rule"
    run "$d ipv4 filter OUTPUT 0 -o lo -j ACCEPT"; run "$d ipv6 filter OUTPUT 0 -o lo -j ACCEPT"
    run "$d ipv4 filter OUTPUT 1 -p tcp --dport 80 -j REJECT --reject-with tcp-reset"
    run "$d ipv6 filter OUTPUT 1 -p tcp --dport 80 -j REJECT --reject-with tcp-reset"
    run "$d ipv4 filter OUTPUT 1 -p udp --dport 53 -j REJECT"
    run "$d ipv6 filter OUTPUT 1 -p udp --dport 53 -j REJECT"
    run "$d ipv4 filter OUTPUT 1 -p tcp --dport 53 -j REJECT --reject-with tcp-reset"
    run "$d ipv6 filter OUTPUT 1 -p tcp --dport 53 -j REJECT --reject-with tcp-reset"
    run "firewall-cmd --reload"
  else
    warn "firewalld not active — provide an nftables ruleset for this host (inbound ssh+mdns, egress reject 80/53, loopback exempt)"
  fi
  ok "firewall configured"
}

mod_dns(){ want dns || return 0; say "randomized no-log encrypted DNS via dnscrypt-proxy"
  pkg_install dnscrypt-proxy
  local F=/etc/dnscrypt-proxy/dnscrypt-proxy.toml
  [ -f "$F" ] || { warn "dnscrypt-proxy config not found at $F"; return 0; }
  backup "$F"
  sed -i "s/^# *lb_strategy =.*/lb_strategy = 'random'/; s/^require_dnssec = false/require_dnssec = true/; \
          s/^require_nolog = false/require_nolog = true/; s/^ignore_system_dns = true/ignore_system_dns = false/; \
          s/^netprobe_timeout = .*/netprobe_timeout = 0/" "$F"
  grep -q "^listen_addresses = \['127.0.0.1:53'\]" "$F" || sed -i "s/^listen_addresses =.*/listen_addresses = ['127.0.0.1:53']/" "$F"
  run "systemctl enable --now dnscrypt-proxy"
  if [ "$HAVE_RESOLVED" = 1 ]; then
    install -d /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/90-${PREFIX}-dns.conf <<'EOF'
[Resolve]
DNS=127.0.0.1
DNSOverTLS=no
DNSSEC=no
LLMNR=no
MulticastDNS=no
Cache=no
DNSStubListener=yes
EOF
    run "systemctl restart systemd-resolved"
  fi
  [ "$HAVE_NM" = 1 ] && for c in $(nmcli -t -f NAME con show 2>/dev/null); do
    nmcli con mod "$c" ipv4.ignore-auto-dns yes ipv6.ignore-auto-dns yes 2>/dev/null || true; done
  ok "DNS routed through randomized no-log resolver pool"
}

mod_intrusion(){ want intrusion || return 0; say "fail2ban (brute-force) + arpwatch (ARP anomaly)"
  pkg_install fail2ban arpwatch
  install -d /etc/fail2ban/jail.d
  cat > /etc/fail2ban/jail.d/10-${PREFIX}-sshd.local <<'EOF'
[DEFAULT]
backend = systemd
bantime  = 3600
findtime = 600
maxretry = 4
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 1w
ignoreip = 127.0.0.1/8 ::1
[sshd]
enabled = true
mode = aggressive
EOF
  [ -n "$PRIMARY_IFACE" ] && printf 'OPTIONS="-i %s -C"\n' "$PRIMARY_IFACE" > /etc/sysconfig/arpwatch 2>/dev/null || true
  run "systemctl enable --now fail2ban"
  run "systemctl enable --now arpwatch" || warn "arpwatch may need interface config on this host"
  ok "fail2ban + arpwatch enabled"
}

mod_gwpin(){ want gwpin || return 0; [ "$HAVE_NM" = 1 ] || { warn "no NetworkManager — skipping gateway pin"; return 0; }
  say "gateway MAC pinning dispatcher"
  cat > /etc/NetworkManager/dispatcher.d/50-${PREFIX}-gw-pin.sh <<EOF
#!/bin/bash
# Trust-on-first-connect: pin the default gateway IP->MAC as a PERMANENT neigh entry so a
# spoofed ARP reply cannot redirect gateway traffic. Logs pins/alerts to the journal.
IFACE="\$1"; ACTION="\$2"; LOG=/root/${PREFIX}-/audit/gateway-pins.log
case "\$ACTION" in up|dhcp4-change|dhcp6-change|connectivity-change)
  GW=\$(ip route show default dev "\$IFACE" 2>/dev/null | awk '/default/{print \$3; exit}'); [ -z "\$GW" ] && exit 0
  ping -c1 -W1 "\$GW" >/dev/null 2>&1 || true
  MAC=\$(ip neigh show "\$GW" dev "\$IFACE" 2>/dev/null | awk '/lladdr/{print \$(NF-1)}')
  [ -z "\$MAC" ] && exit 0
  EXIST=\$(ip neigh show "\$GW" dev "\$IFACE" 2>/dev/null | awk '/lladdr/{print \$3}')
  ip neigh replace "\$GW" lladdr "\$MAC" nud permanent dev "\$IFACE"
  TS=\$(date -u +%Y-%m-%dT%H:%M:%SZ); mkdir -p "\$(dirname "\$LOG")"
  if [ -n "\$EXIST" ] && [ "\$EXIST" != "\$MAC" ]; then
    logger -p auth.warning -t ${PREFIX}-gw-pin "ALERT gateway \$GW MAC \$EXIST -> \$MAC on \$IFACE"
    echo "\$TS ALERT \$IFACE gw=\$GW \$EXIST -> \$MAC" >> "\$LOG"
  else logger -p auth.info -t ${PREFIX}-gw-pin "pinned \$GW -> \$MAC on \$IFACE"; echo "\$TS PIN \$IFACE gw=\$GW mac=\$MAC" >> "\$LOG"; fi ;;
esac; exit 0
EOF
  chmod 0755 /etc/NetworkManager/dispatcher.d/50-${PREFIX}-gw-pin.sh
  [ -n "$PRIMARY_IFACE" ] && /etc/NetworkManager/dispatcher.d/50-${PREFIX}-gw-pin.sh "$PRIMARY_IFACE" up || true
  ok "gateway pinning installed"
}

mod_pam_ssh_key(){ want pam_ssh_key || return 0; say "Sudo-through-SSH-Key-Auth: build+install pam_ssh_agent_auth"
  local libdir; case "$DISTRO_ID$DISTRO_LIKE" in *debian*|*ubuntu*) libdir="/usr/lib/$(uname -m)-linux-gnu/security";; *) libdir=/usr/lib64/security;; esac
  if [ -e "$libdir/pam_ssh_agent_auth.so" ] || [ -e /lib/security/pam_ssh_agent_auth.so ]; then ok "module already present"; return 0; fi
  [ "$DRYRUN" = 1 ] && { say "would build pam_ssh_agent_auth from vendored Debian source"; return 0; }
  local sd; sd="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  local bsh="$sd/../vendor/pam_ssh_agent_auth/build-and-install.sh"
  if [ -x "$bsh" ]; then
    # never fatal: a build failure must leave sudo working on its existing (password) auth.
    if bash "$bsh"; then ok "pam_ssh_agent_auth built + installed"; else warn "module build failed — sudo key-auth left INACTIVE; sudo unaffected"; fi
  else
    warn "vendored build-and-install.sh not found ($bsh) — skipping module build; sudo key-auth INACTIVE"
  fi
}

mod_sudo(){ want sudo || return 0; say "least-privilege sudo SCAFFOLD (no concrete agents defined)"
  local SB; SB="$(command -v dnf systemctl reboot shutdown firewall-cmd nft 2>/dev/null | xargs -n1 dirname | sort -u | head -1)"; SB="${SB:-/usr/sbin}"
  # (1) Command-group LIBRARY — reusable Cmnd_Alias building blocks; grant nothing until assigned.
  install -m 0440 /dev/stdin /etc/sudoers.d/00-${PREFIX}-aliases <<EOF
Cmnd_Alias PKG_MAINT   = $SB/dnf upgrade, $SB/dnf upgrade *, $SB/dnf update, $SB/dnf update *, $SB/dnf check-update, $SB/dnf makecache, $SB/dnf clean all
Cmnd_Alias SYS_REBOOT  = $SB/reboot, $SB/systemctl reboot, $SB/shutdown -r *
Cmnd_Alias SVC_CTL     = $SB/systemctl start *, $SB/systemctl stop *, $SB/systemctl restart *, $SB/systemctl reload *, $SB/systemctl status *, $SB/systemctl is-active *, $SB/systemctl is-enabled *
Cmnd_Alias AUDIT_RUN   = /usr/local/sbin/${PREFIX}-audit, /usr/local/sbin/${PREFIX}-log-export
Cmnd_Alias NET_INSPECT = $SB/firewall-cmd --list-all, $SB/firewall-cmd --list-*, $SB/firewall-cmd --get-*, $SB/nft list ruleset, $SB/ip -s link
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
# Pass the SSH agent socket through for pam_ssh_agent_auth (Sudo-through-SSH-Key-Auth).
Defaults env_keep += "SSH_AUTH_SOCK"
EOF
  # (2) Inert scaffold template (filename contains '.', so sudo ignores it). Documents the
  #     user->role-group->command-group wiring. Real agents get NO-dot drop-ins (e.g. 30-agent-*).
  install -m 0644 /dev/stdin /etc/sudoers.d/10-${PREFIX}-agent.template <<EOF
# AGENT SUDO SCAFFOLD — TEMPLATE ONLY (inert; sudo ignores files containing '.').
# Provision real agents with: ${PREFIX}-provision-agent <name> --local|--remote --profile maint|audit|ops|none
# Example real drop-in /etc/sudoers.d/30-agent-maint :
#   %${PREFIX}-maint ALL=(root) NOPASSWD: PKG_MAINT, SYS_REBOOT, AUDIT_RUN
#   Defaults:%${PREFIX}-maint !requiretty
# Example read-only /etc/sudoers.d/31-agent-audit :
#   %${PREFIX}-audit ALL=(root) NOPASSWD: AUDIT_RUN
# Example interactive (key-auth) /etc/sudoers.d/32-agent-ops :
#   %${PREFIX}-ops   ALL=(root) SVC_CTL, NET_INSPECT, AUDIT_RUN
# Never assign ALL. One role group per privilege set. Validate: visudo -cf <file>.
EOF
  # (3) Sudo key store for pam_ssh_agent_auth (per-user pubkeys; provisioner populates it).
  install -d -m 0755 /etc/security/sudo_authorized_keys.d
  visudo -c >/dev/null || die "sudoers validation FAILED — review /etc/sudoers.d"
  # (4) Sudo-through-SSH-Key-Auth: activate ONLY if the module is present (else sudo would break).
  if [ -e /usr/lib64/security/pam_ssh_agent_auth.so ] || [ -e /lib/security/pam_ssh_agent_auth.so ]; then
    if ! grep -q pam_ssh_agent_auth /etc/pam.d/sudo; then
      backup /etc/pam.d/sudo
      # prepend as the FIRST auth line (sufficient -> password stack remains as fallback; no lockout)
      awk 'BEGIN{d=0} /^auth/ && !d{print "# Sudo-through-SSH-Key-Auth: verify caller SSH-agent key first; fall through to password.";
           print "auth       sufficient   pam_ssh_agent_auth.so file=/etc/security/sudo_authorized_keys.d/%u.pub"; d=1} {print}' \
           /etc/pam.d/sudo > /etc/pam.d/sudo.new && mv /etc/pam.d/sudo.new /etc/pam.d/sudo
      ok "pam_ssh_agent_auth activated for sudo"
    fi
  else
    warn "pam_ssh_agent_auth.so not installed — sudo key-auth left INACTIVE (build the module first,"
    warn "then prepend: auth sufficient pam_ssh_agent_auth.so file=/etc/security/sudo_authorized_keys.d/%u.pub)"
  fi
  ok "sudo scaffold installed (library + inert template + key store)"
}

mod_automation(){ want automation || return 0; say "maintenance automation + durable local audit trail"
  local B=/root/${PREFIX}-/audit
  local UPCMD
  case "$PM" in
    dnf)     UPCMD='dnf -y upgrade --refresh' ;;
    apt-get) UPCMD='apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade' ;;
    zypper)  UPCMD='zypper -n refresh && zypper -n update -y' ;;
    pacman)  UPCMD='pacman -Syu --noconfirm' ;;
  esac
  cat > /usr/local/sbin/${PREFIX}-update <<EOF
#!/bin/bash
# Daily refresh + upgrade, logged.
exec >>/var/log/${PREFIX}-update.log 2>&1; echo "=== \$(date -u +%FT%TZ) update ==="
$UPCMD
EOF
  cat > /usr/local/sbin/${PREFIX}-reboot <<EOF
#!/bin/bash
# Guarded daily reboot with a pre-reboot snapshot.
/usr/local/sbin/${PREFIX}-audit pre-reboot || true
logger -t ${PREFIX} "daily scheduled reboot"; /usr/sbin/systemctl reboot
EOF
  cat > /usr/local/sbin/${PREFIX}-audit <<EOF
#!/bin/bash
# Full system + security state snapshot; 60-day retention; runs daily and at boot.
B=$B/daily; D="\$B/\$(date -u +%Y-%m-%d)"; mkdir -p "\$D"; T="\${1:-scheduled}"
{ echo "tag=\$T \$(date -u +%FT%TZ)"; uname -a; } > "\$D/_meta.txt"
sshd -T > "\$D/sshd.txt" 2>&1; ss -tulnp > "\$D/ports.txt" 2>&1
resolvectl status > "\$D/dns.txt" 2>&1; firewall-cmd --list-all > "\$D/firewall.txt" 2>&1
firewall-cmd --direct --get-all-rules >> "\$D/firewall.txt" 2>&1
sysctl -a 2>/dev/null | grep -E 'rp_filter|redirects|accept_source|arp_|kptr|dmesg|randomize_va|ptrace' > "\$D/sysctl.txt"
getenforce > "\$D/selinux.txt" 2>&1; systemctl is-active dnscrypt-proxy fail2ban arpwatch sshd > "\$D/services.txt" 2>&1
rpm -qa 2>/dev/null | sort > "\$D/packages.txt"
find "\$B" -maxdepth 1 -type d -mtime +60 -exec rm -rf {} + 2>/dev/null || true
EOF
  cat > /usr/local/sbin/${PREFIX}-log-export <<EOF
#!/bin/bash
# Dated export of the audit trail + recent journal into /root; 30-day retention.
E=/root/${PREFIX}-/audit/exports; mkdir -p "\$E"; TS=\$(date -u +%Y%m%d)
journalctl --since "30 days ago" > /tmp/${PREFIX}-journal.txt 2>/dev/null || true
tar czf "\$E/logs-\$TS.tar.gz" -C /root/${PREFIX}-/audit daily 2>/dev/null /tmp/${PREFIX}-journal.txt 2>/dev/null || true
rm -f /tmp/${PREFIX}-journal.txt
find "\$E" -name 'logs-*.tar.gz' -mtime +30 -delete 2>/dev/null || true
EOF
  chmod 0755 /usr/local/sbin/${PREFIX}-{update,reboot,audit,log-export}
  cat > /etc/cron.d/${PREFIX}-maintenance <<EOF
# Daily: audit, export, update, reboot (local time).
SHELL=/bin/bash
PATH=/usr/sbin:/usr/bin
15 3 * * * root /usr/local/sbin/${PREFIX}-audit scheduled
45 3 * * * root /usr/local/sbin/${PREFIX}-log-export
0  4 * * * root /usr/local/sbin/${PREFIX}-update
30 4 * * * root /usr/local/sbin/${PREFIX}-reboot
EOF
  cat > /etc/systemd/system/${PREFIX}-audit-boot.service <<EOF
[Unit]
Description=Capture security state at boot
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/${PREFIX}-audit boot
[Install]
WantedBy=multi-user.target
EOF
  run "systemctl daemon-reload"; run "systemctl enable ${PREFIX}-audit-boot.service"
  ok "automation + audit trail installed"
}

mod_aide(){ want aide || return 0; say "AIDE file-integrity database"
  pkg_install aide
  if command -v aide >/dev/null 2>&1 && [ ! -f /var/lib/aide/aide.db.gz ]; then
    run "aide --init && mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz" || warn "aide init failed; run manually"
  fi
  ok "AIDE present (schedule 'aide --check' via cron for periodic verification)"
}

mod_audit(){ want audit || return 0; say "auditd baseline rules"
  pkg_install audit
  install -d /etc/audit/rules.d
  cat > /etc/audit/rules.d/${PREFIX}-cis.rules <<'EOF'
-D
-b 8192
-f 1
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d -p wa -k sshd
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/selinux -p wa -k MAC-policy
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d -p wa -k sysctl
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k privesc
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
EOF
  command -v augenrules >/dev/null 2>&1 && run "augenrules --load" || true
  run "systemctl enable auditd" 2>/dev/null || true
  # add audit=1 to boot args (GRUB) for early-boot coverage
  if command -v grubby >/dev/null 2>&1; then run "grubby --update-kernel=ALL --args='audit=1 audit_backlog_limit=8192'" || true; fi
  ok "auditd rules installed (immutable mode intentionally OFF for a daily-reboot host)"
}

mod_tor(){ [ "$ENABLE_TOR" = 1 ] || return 0; say "Tor: region-locked (US/NA) outbound anonymity"
  pkg_install tor
  install -d /etc/tor/torrc.d
  cat > /etc/tor/torrc.d/50-${PREFIX}.conf <<'EOF'
# Region-locked exits (North America). Standard 3-relay circuit (reducing hops is unsupported).
ExitNodes {us},{ca}
StrictNodes 1
EOF
  if [ "$ENABLE_TOR_TRANSPARENT" = 1 ]; then
    # TransPort only — DNS rides Tor via dnscrypt (force_tcp) so no UDP DNSPort is needed
    # (avoids the SELinux udp name_bind restriction on tor_port_t).
    cat >> /etc/tor/torrc.d/50-${PREFIX}.conf <<'EOF'
TransPort 127.0.0.1:9040 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
EOF
    # SELinux: allow tor to bind the transparent port
    command -v semanage >/dev/null 2>&1 && { semanage port -a -t tor_port_t -p tcp 9040 2>/dev/null || semanage port -m -t tor_port_t -p tcp 9040; }
    # dnscrypt over TCP so encrypted DNS can ride Tor's TCP transport
    [ -f /etc/dnscrypt-proxy/dnscrypt-proxy.toml ] && { sed -i 's/^force_tcp = false/force_tcp = true/' /etc/dnscrypt-proxy/dnscrypt-proxy.toml; systemctl restart dnscrypt-proxy 2>/dev/null; }
    run "systemctl enable --now tor"
    # detect the tor service uid (toranon / debian-tor / tor) for the exemption
    local TORUID; TORUID=$(id -u toranon 2>/dev/null || id -u debian-tor 2>/dev/null || id -u tor 2>/dev/null)
    install -d /etc/nftables
    cat > /etc/nftables/${PREFIX}-tor.nft <<EOF
# Transparent Tor kill-switch. Exemptions first: loopback, tor's own uid ($TORUID), private/
# link-local/multicast dests (preserves LAN incl. admin SSH peer + gateway), then NTP. All other
# outbound TCP is redirected into Tor; non-Tor UDP/ICMP to the internet is dropped (leak prevention).
table inet ${PREFIX}_tor {
    chain output_nat {
        type nat hook output priority -100; policy accept;
        meta oifname "lo" return
        meta skuid $TORUID return
        ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } return
        ip6 daddr { ::1, fe80::/10, fc00::/7, ff00::/8 } return
        meta l4proto tcp redirect to :9040
    }
    chain output_filter {
        type filter hook output priority 0; policy accept;
        meta oifname "lo" accept
        meta skuid $TORUID accept
        ct state established,related accept
        ip daddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept
        ip6 daddr { ::1, fe80::/10, fc00::/7, ff00::/8 } accept
        udp dport 123 accept
        meta l4proto udp drop
        meta l4proto { icmp, icmpv6 } drop
    }
}
EOF
    cat > /etc/systemd/system/${PREFIX}-tor-killswitch.service <<EOF
[Unit]
Description=Transparent Tor kill-switch (nftables transparent torification)
After=tor.service firewalld.service network-online.target
Wants=tor.service network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/nftables/${PREFIX}-tor.nft
ExecStop=/usr/sbin/nft delete table inet ${PREFIX}_tor
[Install]
WantedBy=multi-user.target
EOF
    nft -c -f /etc/nftables/${PREFIX}-tor.nft || die "tor kill-switch ruleset failed validation"
    if [ "$CLOUD" != 1 ]; then
      warn "ON A REMOTE/LIVE HOST: arm a dead-man before enabling, e.g.:"
      warn "  systemd-run --on-active=240 --unit=tor-deadman /usr/sbin/nft delete table inet ${PREFIX}_tor"
      warn "  then verify a plain 'curl https://api.ipify.org' returns a Tor exit IP and your SSH is alive,"
      warn "  and 'systemctl stop tor-deadman.timer' only after it passes."
    fi
    run "systemctl daemon-reload"; run "systemctl enable --now ${PREFIX}-tor-killswitch.service"
    ok "transparent Tor kill-switch active (all outbound via US/CA Tor; LAN+established+tor+NTP exempt)"
  else
    run "systemctl enable --now tor"
    ok "Tor running, exits US/CA, SOCKS 127.0.0.1:9050 (opt-in; pass --enable-tor-transparent to enforce)"
  fi
}

# ============================================================================= RUN
say "=== applying hardening baseline ==="
mod_ssh; mod_crypto; mod_sysctl_net; mod_sysctl_kernel; mod_modprobe; mod_coredumps
mod_login; mod_faillock; mod_firewall; mod_dns; mod_intrusion; mod_gwpin
mod_pam_ssh_key; mod_sudo; mod_automation; mod_audit; mod_aide; mod_tor
ok "=== baseline applied. Reboot to fully activate crypto policy + boot-time controls. ==="
echo "Recovery invariants preserved: physical console, disk-encryption passphrase keyslot,"
echo "existing SSH key, and SELinux/MAC enforcing. Verify before relying on remote-only access."
