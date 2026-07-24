---
type: Decision Log
title: Security Decision Log
description: Chronological, append-only record of every security decision in this baseline — what changed, why, how, the CIS deviation if any, and the rollback.
tags: [decision-log, rationale, rollback, cis-deviation, hardening]
status: stable
generated:
  by: claude-code/opus-5
  at: 2026-07-24T19:01:22-04:00
sources:
  - resource: /CONTROLS.md
    title: Control set distilled from this log
---

# Secure Hardening Baseline — Security Decision Log

> Documentation framing: this records the security choices for a current, security- and
> anonymity-focused configuration (CIS L1 + enterprise controls). No product codename, business
> purpose, or personal intent is implied; "operator" denotes whoever administers the host.


Chronological, append-only record of every security decision and implementation. Each entry:
**what, why, how, deviation-from-CIS (if any), rollback.** Companion to `ARCHITECTURE.md`.

Format key: ✅ implemented · ⏳ pending · ⚠️ intentional CIS deviation · 🔁 rollback noted.

---

## 2026-06-29 — Session 2: CIS L1 hardening + enterprise security controls

### D000 — Baseline captured ✅
Pre-change state snapshotted to `audit/baseline/` (sshd -T, crypto policy, listening ports,
resolvectl, security sysctls, firewall, enabled units, SELinux, lsmod, full package list, original
sshd_config + sshd_config.d). Rollback reference for every subsequent change.

### D001 — Agent sudo model: dedicated least-privilege service account ✅(decided)
**Decision:** Create a non-login `agent` service account + `secbase-*` groups; scope sudo via
`Cmnd_Alias` groups in `/etc/sudoers.d`. Rejected blanket `%wheel NOPASSWD: ALL`.
**Why:** Enterprise least privilege; the command whitelist is the security boundary for unattended
automation. Per owner, policy must be delineable by group and user.

### D002 — Secure DNS: Quad9 + DNS-over-TLS + DNSSEC ✅(decided)
**Decision:** `9.9.9.9` / `149.112.112.112`, `DNSOverTLS=yes`, `DNSSEC=yes`.
**Why:** Malware/phishing blocklist, validated + encrypted resolution, resists on-path DNS tamper.
No-logging Swiss operator. CIS-aligned (encrypted DNS exceeds L1).

### D003 — Daily update + reboot at 04:00 / 04:30 ✅(decided)
**Decision:** `secbase-update` 04:00, `secbase-reboot` 04:30 local (America/New_York).
**Why:** Off-hours; updates stage before reboot applies them. Reboot survival is a tested property.

### D004 — SSH: key-only, no root login, CIS limits, FUTURE crypto ✅ IMPLEMENTED
Drop-in `01-secbase-hardening.conf` (sorts first, wins). `sshd -t` OK, reloaded. Verified effective.
Also `AllowTcpForwarding no`, `AllowAgentForwarding no`, `LogLevel VERBOSE`, GSSAPI off.
Crypto policy → FUTURE (full apply at reboot; sshd back-end regenerated + reloaded now).
**Lockout check:** owner's live session (<workstation-ip>) authed by **publickey** ED25519
SHA256:AA4j3Spl… == authorized_keys. Key-only reconnect confirmed safe. Console + key fallback intact.
**Decision:** `PasswordAuthentication no`, `PermitRootLogin no`, `MaxAuthTries 4`,
`LoginGraceTime 60`, `ClientAliveInterval 300`/`ClientAliveCountMax 0`, banner none. System crypto
policy → **FUTURE** (drops SHA-1 MAC, legacy KEX). `<owner>` ed25519 key verified present first.
**Why:** CIS L1 SSH controls; physical console remains as lockout fallback.
**⚠️ Deviation:** `X11Forwarding yes` retained (CIS L1 wants `no`) — owner accepts as a convenience
tool. Documented per owner. (CIS 5.x SSH; deviation owner-approved.)

### D005 — Disable LLMNR, keep mDNS ✅ IMPLEMENTED
**Decision:** `LLMNR=no` and `MulticastDNS=no` in systemd-resolved; **keep avahi** answering mDNS
on 5353. **Why:** LLMNR is a well-known name-resolution poisoning / MITM vector and is redundant
with mDNS. Owner explicitly wants mDNS responding, so avahi stays exposed.

### D006 — Anti-MITM sysctl (L2/L3) ✅ IMPLEMENTED
`/etc/sysctl.d/90-secbase-network-hardening.conf`: rp_filter=1, accept_redirects=0 (v4+v6),
send_redirects=0, secure_redirects=0, accept_source_route=0, arp_ignore=1, arp_announce=2,
log_martians=1, icmp bogus/broadcast ignore, IPv6 accept_ra=0, ip_forward=0, tcp_syncookies=1.
Applied via `sysctl --system`; persists across reboot. **Why:** Close ICMP-redirect, source-route,
ARP-spoof assist, rogue-RA on-path surfaces. CIS L1 §3.3.
**Note:** accept_ra=0 disables IPv6 SLAAC autoconfig (rogue-RA defense); IPv4 is primary, SSH is IPv4.

### D002/secure-DNS ✅ IMPLEMENTED (superseded by D014)
resolved drop-in `90-secbase-dns.conf` + `nmcli ipv4/ipv6.ignore-auto-dns yes` so a fixed encrypted
resolver overrode DHCP-pushed ISP DNS (was 68.105.x). Initially Quad9 over DoT; replaced by D014
for query-source anonymity via resolver randomization.

### D014 — Randomized, no-log, encrypted DNS via dnscrypt-proxy ✅ IMPLEMENTED
**Decision:** Resolver chain `resolved stub (127.0.0.53) → dnscrypt-proxy (127.0.0.1:53) → randomized
pool of no-log, DNSSEC-validating encrypted resolvers (DoH/DNSCrypt over 443)`. Config:
`require_nolog=true`, `require_dnssec=true`, `lb_strategy='random'`, `netprobe_timeout=0` (avoids the
plaintext-53 netprobe blocked by egress rules), `ignore_system_dns=false` for first-run bootstrap.
**Why:** spreading queries across many no-logging operators means no single resolver can profile all
lookups — stronger query-source anonymity than any single provider, while staying encrypted +
validated. Supersedes single-provider Quad9 DoT (D002). Verified end-to-end; ISP/Quad9 no longer
used. **Available enhancement:** Anonymized DNS / ODoH relays (resolver never sees client IP) —
documented, not yet enabled pending stability soak. Rollback: restore prior resolved drop-in +
`systemctl disable --now dnscrypt-proxy`.

### D017 — CIS Level 1 baseline ✅ IMPLEMENTED
- **Modules** `modprobe.d/secbase-cis.conf`: disable cramfs/freevxfs/hfs/hfsplus/jffs2/squashfs/
  udf + dccp/sctp/rds/tipc. usb-storage left enabled (workstation USB — deviation).
- **Kernel sysctl** `90-secbase-kernel-hardening.conf`: ASLR=2, kptr_restrict=2, dmesg_restrict=1,
  yama.ptrace_scope=1, suid_dumpable=0, protected_{hardlinks,symlinks,fifos,regular},
  unprivileged_bpf_disabled=1, bpf_jit_harden=2, perf_event_paranoid=3. (userns left enabled so
  browser/flatpak sandboxes work.)
- **Core dumps** off: limits.d + coredump.conf Storage=none.
- **umask 027** (profile.d + login.defs). **Password aging** PASS_MAX_DAYS 365 / PASS_MIN_DAYS 1.
  **pwquality** minlen14/minclass4/cred-1/maxrepeat3/enforce_for_root. ENCRYPT_METHOD already
  YESCRYPT.
- **Lockout** faillock via authselect `with-faillock`: deny=5, unlock 15m, root not locked. PAM
  verified intact.
- **cron/at** restricted to root (cron.allow/at.allow 600, deny removed).
- **auditd**: 43 CIS rules (`rules.d/secbase-cis.rules`) loaded; boot args `audit=1
  audit_backlog_limit=8192` (apply next boot). Not immutable (daily-reboot box).
- **Deferred (live-box breakage risk):** separate /tmp,/var/tmp with nodev,nosuid,noexec — needs a
  maintenance window / subvol change; recommended for a frozen demo image.
Rollback: remove the named drop-in files + `authselect disable-feature with-faillock`.

### D016 — Maintenance automation + durable local audit trail ✅ IMPLEMENTED
Scripts in `/usr/local/sbin`: `secbase-update` (daily `dnf --refresh upgrade`, logged),
`secbase-reboot` (daily guarded reboot + pre-reboot snapshot), `secbase-audit` (full
system+security state → `audit/daily/<date>/`, **60-day** retention, pkg-drift diff),
`secbase-log-export` (dated tar.gz of audit trail + 24h/30d journal → `exports/`, **30-day**
retention). Cron `/etc/cron.d/secbase-maintenance`: 03:15 audit, 03:45 export, 04:00 update,
04:30 reboot (local). Boot persistence: `secbase-audit-boot.service` runs an audit at every boot
so the trail has no gaps regardless of reboot. All controls persist via sysctl.d/sshd_config.d/
systemd/firewalld-permanent → system returns hardened after reboot. Tested: audit + export
produce output; units enabled. **Why:** no external log server (documented bypass) → local 60-day
state trail + 30-day exports. Rollback: remove cron file + `systemctl disable --now
secbase-audit-boot`.

### D015 — Encrypted-egress-only: block outbound plaintext HTTP(80) + DNS(53) ✅ IMPLEMENTED
firewalld direct rules, OUTPUT chain: loopback exempt (priority 0), then REJECT tcp/80 and udp+tcp/53
(v4+v6). **Why:** forces HTTPS + encrypted DNS only; prevents plaintext-DNS leaks and cleartext HTTP
exfil/MITM. Verified: HTTPS 200 / HTTP blocked / plaintext :53 refused / DoH resolution intact.
Rollback: `firewall-cmd --permanent --direct --remove-rules ...` (see direct.xml) + reload.

### D009 — Firewall: exactly ssh + mdns; denied logging ✅ IMPLEMENTED
firewalld public zone trimmed to `ssh`,`mdns` (removed dhcpv6-client). `--set-log-denied=all` for
audit trail. Default target = deny inbound. **Verified non-localhost listeners = only sshd:22 +
avahi:5353; LLMNR:5355 CLOSED.** Matches owner directive (localhost-only except SSH + mDNS).
Rollback: `firewall-cmd --permanent --zone=public --add-service=dhcpv6-client; --set-log-denied=off`.

### D001/D007 — Agent identities + delineated sudo ✅ IMPLEMENTED
Groups `secbase-ops` (scoped operators), `secbase-agents` (service agents). Service account `agent`
(nologin, own ed25519 key). sudoers.d, all `visudo`-validated, 0440:
`00-secbase-aliases` (Cmnd_Alias PKG_MAINT/SYS_REBOOT/SVC_CTL/AUDIT_RUN/NET_INSPECT + CIS
`use_pty`+`logfile=/var/log/sudo.log`); `10-agent` (`agent` NOPASSWD PKG_MAINT/SYS_REBOOT/AUDIT_RUN;
`%secbase-agents` NOPASSWD AUDIT_RUN); `20-secbase-ops` (`%secbase-ops` SVC_CTL/AUDIT_RUN/NET_INSPECT,
auth required). No blanket ALL/NOPASSWD. Provisioning standard: `/usr/local/sbin/secbase-provision-agent
<name> [--remote|--local] [--ops]` — creates account, generates ed25519 key, self-enrols pubkey for
remote agents (loopback ssh-copy-id pattern), joins group, logs to `audit/agent-provisioning.log`.
Smoke-tested + cleaned up. Rollback: remove `/etc/sudoers.d/{00-secbase-aliases,10-agent,20-secbase-ops}`.

### D007-prior — Agents are key-bearing identities; standard provisioning process ⏳→see D001/D007
**Decision:** Each agent (remote-capable or local service) is provisioned by
`secbase-provision-agent`: create account → generate ed25519 key → self-enrol pubkey (loopback
`ssh-copy-id` pattern for remote-capable; sudo key-store for all) → join `secbase-*` group.
**Why (owner):** Agents may lack keys; generate one as standard process. The key is the universal
credential for both SSH and sudo, uniformly across remote users and local service accounts.

### D008 — Key-required sudo mechanism ✅ RESOLVED → see D008 (Sudo-through-SSH-Key-Auth) below
Resolved as option (a): build `pam_ssh_agent_auth` from a trusted distro source. Owner chose the
**Debian patched source**; provenance was authenticated end-to-end (GPG-signed `.dsc`). Full record,
verification, and rollback are in the later D008 entry. (b) `pam_u2f` rejected: per-agent hardware is a
poor fit for headless service accounts. Automation path still also uses scoped `NOPASSWD` (no human
secret in loop).

### D011 — fail2ban (SSH brute-force) + arpwatch (ARP anomaly detection) ✅ IMPLEMENTED
fail2ban: `jail.d/10-secbase-sshd.local`, systemd backend, maxretry=4, findtime=10m, bantime=1h
with incremental escalation (×2, cap 1w), bans via firewalld. arpwatch: monitors wlp1s0, logs ARP
changes/flip-flops to journal. Both enabled at boot. **Why:** brute-force lockout + on-LAN
ARP-spoof detection. Rollback: remove jail file / `systemctl disable --now fail2ban arpwatch`.

### D012 — Gateway MAC pinning (anti ARP-spoof) ✅ IMPLEMENTED
NM dispatcher `50-secbase-gw-pin.sh`: on connect/DHCP-change, trust-on-first-connect pins the
default-gateway IP→MAC as a PERMANENT neigh entry per interface; logs pins + alerts on MAC change to
journal + `audit/gateway-pins.log`. Pinned <gateway-ip>→<gateway-mac>. **Why:** a spoofed ARP
reply cannot redirect gateway traffic once pinned; complements arpwatch. Rollback: delete dispatcher
+ `ip neigh flush nud permanent`.

### D013 — "Tor Light": region-locked transparent Tor for outbound ⏳ IN PROGRESS
**Owner request:** route outbound traffic through Tor, exit region-locked to North America/US.
**Design:** tor as transparent proxy (TransPort+DNSPort) with `ExitNodes {us}` (fallback {us},{ca}),
`StrictNodes 1`. Hop count stays at Tor default 3 (reducing below 3 is unsupported + breaks
anonymity; "2-3 proxies" satisfied by the default 3-relay circuit). nftables redirects outbound TCP
+ DNS to Tor, with mandatory exemptions: loopback, **LAN subnet + established/related (preserves
owner's inbound SSH)**, the `tor` user's own traffic, and **NTP/UDP 123 direct** (Tor needs correct
clock; Tor can't carry UDP). mDNS stays link-local/direct. **Why staged:** a torify kill-switch on a
remotely-administered box can sever SSH + break the daily updater; applied with exemptions + tested.

### D013 — ✅ IMPLEMENTED (transparent kill-switch active)
torrc.d `50-secbase.conf`: `ExitNodes {us},{ca}`, `StrictNodes 1`, `TransPort 127.0.0.1:9040`
(isolation flags). No Tor DNSPort — encrypted DNS rides Tor via dnscrypt `force_tcp=true`
(also avoids SELinux udp `name_bind` on `tor_port_t`). SELinux kept **Enforcing**: labeled 9040/tcp
`tor_port_t` via `semanage` (not a permissive shim). nftables table `inet secbase_tor`
(`/etc/nftables/secbase-tor.nft`): exemptions ordered first — loopback, tor uid 966, RFC1918 +
link-local + multicast dests (preserves LAN/SSH peer/gateway), NTP/123 — then redirect all other
outbound TCP → :9040; drop non-Tor UDP/ICMP to internet. Persisted via
`secbase-tor-killswitch.service` (After=tor). **Verified:** plain `curl https://api.ipify.org`
returned Tor exit `<tor-exit-ip>`; DNS OK; LAN/gateway OK; owner SSH session stayed ESTABLISHED.
Applied behind a **systemd-timer dead-man** (auto-revert) that was cancelled only after verification.
Rollback: `systemctl disable --now secbase-tor-killswitch` (+ remove torrc.d drop-in).
**Boot note:** ~30–60s after each reboot, web/DNS wait for Tor to bootstrap (SSH/LAN unaffected).

### D019 — Crypto policy reverted FUTURE → DEFAULT; SSH algorithms pinned ✅ IMPLEMENTED
**Correction to D004.** FUTURE rejected RSA-2048 certificate chains (all Let's Encrypt RSA certs +
much of the web): `curl https://check.torproject.org` returned `000` under FUTURE, `200` under
DEFAULT. FUTURE would have broken normal HTTPS and the dnf auto-updater. **Fix:** system policy →
**DEFAULT** (still strong: TLS1.2+, no SHA-1 signatures, no weak ciphers; CIS-acceptable) while
**pinning modern SSH algorithms explicitly** in `01-secbase-hardening.conf` (chacha20/aes-gcm
ciphers, sha2-512/256-etm MACs, sntrup761x25519 + curve25519 KEX, ed25519/rsa-sha2 host+pubkey) so
SSH stays hardened regardless of system policy. Verified web TLS restored + SSH still hardened.
Rollback: `update-crypto-policies --set FUTURE` (not recommended) / remove pinned lines.

### D020 — Sudo redesigned: agent SCAFFOLD instead of a concrete account ✅ IMPLEMENTED
**Supersedes D001.** Removed the concrete `agent` user + `secbase-agents`/`secbase-ops` groups +
`10-agent`/`20-secbase-ops` assignments. New model supports many future agents:
- `00-secbase-aliases` — **command-group library** (`Cmnd_Alias` PKG_MAINT/SYS_REBOOT/SVC_CTL/
  AUDIT_RUN/NET_INSPECT) + `Defaults use_pty,logfile` + `env_keep += SSH_AUTH_SOCK`. Grants nothing
  until assigned.
- `10-secbase-agent.template` — **inert** scaffold (sudo ignores files containing `.`) documenting
  the user→role-group→command-group wiring with per-profile examples (maint/audit/ops/single-user).
- `secbase-provision-agent <name> [--local|--remote] [--profile maint|audit|ops|none]` —
  creates per-agent account + ed25519 key, joins the role group, idempotently drops a **validated**
  no-dot role file, and installs the agent's pubkey to the sudo key store. **No agents are defined**
  — provisioning is on demand. Each agent = least privilege via its role's command-group(s).
Rollback: remove the named files. visudo -c clean.

### D008 — Sudo-through-SSH-Key-Auth (pam_ssh_agent_auth) ✅ IMPLEMENTED
**What:** sudo authenticates by SSH-agent key. `auth sufficient pam_ssh_agent_auth.so
file=/etc/security/sudo_authorized_keys.d/%u.pub` is the FIRST auth line in `/etc/pam.d/sudo`;
password stack stays below as fallback (no lockout). `Defaults env_keep += SSH_AUTH_SOCK` lets the
module see the agent. Per-caller key store `…/%u.pub` seeded with <owner>'s key; provisioner adds one
`<name>.pub` per agent.
**Source (owner chose: Debian patched source).** Module is NOT in Fedora/EPEL/RHEL (verified: koji,
dist-git, EPEL 8/9/10, EL8/EL7 vaults). Built from Debian src pkg `pam-ssh-agent-auth` 0.10.3-11.
Authenticated chain: snapshot.debian.org by-hash → sha1 OK → `.dsc` sha256 == both tarballs → `.dsc`
PGP **GOOD**, signer Petter Reinholdtsen `<pere@debian.org>` fpr `3AC7B2E3ACA5DF8778F1D827111D6B29EE4E02F9`,
confirmed in Debian's developer DB. Vendored at `vendor/pam_ssh_agent_auth/` (src + `.so` + `SHA256SUMS`
+ `PROVENANCE.md` + idempotent `build-and-install.sh`).
**Build:** 8 Debian patches (OpenSSL-1.1/3, gcc-14, ECDSA segfault, sha256 fp). Hardened CFLAGS +
full RELRO/BIND_NOW. Installed `/usr/lib64/security/pam_ssh_agent_auth.so` (SELinux `lib_t`).
**Verified:** non-root caller (<owner>) with matching key in its own agent → passwordless sudo (`exit 0`,
log `ssh_ed25519_verify: signature correct` / `grantors=pam_ssh_agent_auth res=success`); no agent →
falls through to password (`exit≠0`). `%u`=invoking user at auth time, so per-caller files are correct.
**Caveat:** `sudo -n` short-circuits before PAM and never invokes the module — test with a tty or
`sudo <cmd> </dev/null`, not `sudo -n`.
**Console path (owner decision):** physical-console interactive sudo intentionally uses
faillock-protected **password** — no local private key at rest. Remote operators get keyless sudo via
forwarded agent (D022); local service accounts via their on-box agent. A local console key
(passphrased, or FIDO2 `-sk`) was offered and **deferred** by the owner; revisit if console
key-sudo is wanted later.
**Rollback:** remove the `pam_ssh_agent_auth` line from `/etc/pam.d/sudo` (or restore
`audit/baseline/pam.d-sudo.*.bak`); optionally `rm /usr/lib64/security/pam_ssh_agent_auth.so`. Sudo
reverts to password/NOPASSWD. **Reboot-safe:** module + PAM + key store are all on-disk; not
RPM-owned, so `dnf` won't remove it (an OpenSSL/PAM ABI bump on update could require a rebuild —
re-run `vendor/pam_ssh_agent_auth/build-and-install.sh`). harden.sh reproduces all of this via
`mod_pam_ssh_key` (never fatal — a build failure leaves sudo working).
**Re-verified 2026-06-30 (post auto-updates):** module loads + authenticates today under SELinux
Enforcing. Throwaway-identity round-trip: key-in-agent → passwordless sudo `exit 0`
(`grantors=pam_ssh_agent_auth res=success`); no agent → denied (key-gated, NOT NOPASSWD). <owner> path
intact — `wheel ALL=(ALL) ALL`, keystore `<owner>.pub` == login key, `env_keep+=SSH_AUTH_SOCK`,
`AllowAgentForwarding yes`. No config changed.

### D022 — SSH agent forwarding ENABLED (for remote key-auth sudo) ✅ IMPLEMENTED
`AllowAgentForwarding yes` (was `no`). Required so remote users/agents can forward their SSH agent
to satisfy `pam_ssh_agent_auth` for sudo (D008) — the key is the universal credential for login AND
sudo. Owner chose **global** enable (over a `Match Group` scoped option). `AllowTcpForwarding`
stays `no`. Risk accepted: a compromised host could use a connected user's forwarded agent for the
session's lifetime; mitigated by key-only login, faillock, and short `ClientAliveInterval`.
Rollback: set `AllowAgentForwarding no`, `sshd -t`, `systemctl reload sshd` (key-auth sudo then works
for LOCAL agents only). Reboot-safe (drop-in config).

### D021 — Tor on/off toggle ✅ IMPLEMENTED
`scripts/toggle_tor.sh {on|off|status}`. `on`: bootstraps tor, applies the nftables kill-switch via
`secbase-tor-killswitch.service`, enables it at boot, and (on a live host) arms a systemd-timer
dead-man that auto-reverts unless a plain `curl` returns a Tor exit IP. `off`: stops+**disables** the
unit (so the daily reboot won't silently re-enable) and restores normal egress (DNS still encrypted,
plaintext 80/53 still blocked). Tested both directions: ON exit `<tor-exit-ip>`; OFF real IP
`<wan-ip>`. `--stop-tor` also stops tor.service; `--no-deadman`/`--deadman N` tune the safety timer.

---

## 2026-06-30 — Session 3: operator account (uid 1000) password reset + age exemption

✅⚠️ **What.** Reset login password for account `<owner>` (uid 1000, group `wheel`) and disabled max
password age for that account only.
**Why.** Operator-managed credential; account exempted from forced rotation at operator direction.
**How.**
- Snapshot `90-secbase.conf` → `configs-backup/90-secbase.conf.20260630.bak`.
- Temporarily set `enforcing = 0` in the pwquality drop-in (complexity → warn-only).
- Password set interactively via `passwd <owner>`; secret typed at the prompt, **not recorded** here.
- Restored drop-in from backup; verified byte-identical and live-tested (`pwscore` rejects weak pw,
  `enforce_for_root` active again).
- `chage -M -1 <owner>` → `Password expires: never`, `Maximum: -1`.
🔁 **Rollback.** Re-enable aging: `chage -M 365 -W 7 <owner>`. Complexity already enforced for this
account's *next* change (full 90-secbase policy live). Relaxation window was seconds; drop-in is
back to baseline.
⚠️ **Note.** Current stored secret for uid 1000 was accepted under relaxed complexity (not re-checked
against minlen14/minclass4). Per operator: it is a single cloud-saved credential (password manager),
not a password shared across other hosts. SSH access to this host is via one ed25519 key, laptop→host
only. Exposure surface is the operator's cloud vault, not multi-host reuse.

---

## 2026-06-30 — Session 4: second admin (`<second-admin>`) + self-service key onboarding

### D033 — `<second-admin>` admin account (mirror of `<owner>`) ✅ IMPLEMENTED
✅ **What.** Second full admin `<second-admin>` (uid 1001, `wheel`), same mechanism as `<owner>`: key-only
SSH login + `pam_ssh_agent_auth` key-store sudo (`ALL=(ALL) ALL` via wheel).
**Why.** Operator wants a second standing admin identity built exactly like `<owner>`.
**How.** `useradd -m -s /bin/bash` + `usermod -aG wheel`. Own ed25519 identity (no shared key). The
box-generated private key was **not** retained at rest (mirrors <owner> — auto-mode classifier also
blocked transcript exposure of it). Operator enrols the real keypair self-service via D034 (currently
staged in `onboarding`). Passwordless-sudo path verified earlier (positive key→root `exit 0`;
negative no-agent→denied).
🔁 **Rollback.** `userdel -r <second-admin>; rm -f /etc/security/sudo_authorized_keys.d/<second-admin>.pub`.

### D034 — Self-service first-key onboarding (scoped LAN password auth + auto-promote) ✅ IMPLEMENTED
✅⚠️ **What.** New users in group `onboarding` may use a **password from the LAN only** to
`ssh-copy-id` their first key; an auto-promotion watcher then makes them a key-only `wheel` admin and
revokes the password path. Onboarding temp passwords age out in **10 days**.
**Why.** The key-only baseline (D004) has no self-service path to install a *first* key — `ssh-copy-id`
needs password auth, and it never touches the sudo key-store anyway. Operator wants devs to onboard
themselves without an admin hand-installing every key.
⚠️ **Deviation from D004 (key-only).** Re-enables `PasswordAuthentication`, but **scoped**:
`Match Group onboarding Address <lan-cidr>` in `sshd_config.d/02-secbase-onboarding.conf`. Global
`PasswordAuthentication no` still applies to all other users — verified by `sshd -T -C`
(onboarding+LAN→`yes`; onboarding off-LAN→`no`; admin→`no`). Contained by: LAN-only scope, fail2ban
(D011), faillock (D017), 10-day password expiry, and the window self-closing on first key upload.
**How.**
- Group `onboarding`; sshd drop-in scoped Match (`sshd -t` OK, reloaded; pre-change `sshd -T`
  snapshot in `audit/baseline/`).
- `/usr/local/sbin/secbase-onboard <user>`: `useradd` → `onboarding` → `chage -M 10` → temp password
  → arms `secbase-promote@<user>.path`.
- `/usr/local/sbin/secbase-promote <user>` (path-unit triggered on `authorized_keys` write;
  idempotent, guarded on onboarding membership + a valid key): login key → sudo key-store, `+wheel`,
  `-onboarding` (revokes password auth), `chage -M 365` (normalise to D017), disables the watcher.
- systemd templated `secbase-promote@.{path,service}` — per-user, `enable`d → reboot-safe.
- SELinux: a benign `init_t → ssh_home_t:file read` denial (PID1 arming the path-watch) is suppressed
  by a **dontaudit-only** module `vendor/selinux/secbase_onboard.te` — grants nothing; promotion
  fires via directory inotify regardless.
- **10-day aging is scoped to onboarding accounts, NOT the global `useradd` default.** A global
  `PASS_MAX_DAYS=10` would expire `<owner>`/`root` and break the console + sudo-password recovery path
  (non-negotiable). `login.defs` default stays 365 (D017).
**Verified.** Two throwaway users end-to-end: scoped password matrix correct; key write → auto-promote
in ~2 s (key-store populated, `+wheel`, `-onboarding`, password auth→`no`, aging→365, watcher off);
zero AVC after the dontaudit module.
🔁 **Rollback.** `rm /etc/ssh/sshd_config.d/02-secbase-onboarding.conf` → reload sshd;
`semodule -r secbase_onboard`; `rm /etc/systemd/system/secbase-promote@.{path,service}` +
`/usr/local/sbin/secbase-{onboard,promote}`; `groupdel onboarding`. All reboot-safe on-disk units.

### D035 — Operator workstation exempt from SSH auth-failure throttling ✅ IMPLEMENTED
✅ **What.** `<workstation-ip>` (operator workstation) added to fail2ban `sshd` `ignoreip` **and** sshd
`PerSourcePenaltyExemptList`.
**Why.** During key onboarding the operator's multi-key agent offers several keys to a target that
hasn't enrolled them yet; with `MaxAuthTries 4` + fail2ban `maxretry 4` this trips an IP-wide ban +
per-source penalty, locking the operator out of **all** accounts (incl. `<owner>`) from that host.
Recurring self-lockout — observed: failed `<second-admin>` pubkey attempts from `.85` banned the IP.
**How.** Snapshots to `configs-backup/` + `audit/baseline/`. fail2ban: append IP to `ignoreip` in
`jail.d/10-secbase-sshd.local` → `fail2ban-client reload`. sshd: `PerSourcePenaltyExemptList
<workstation-ip>` in `sshd_config.d/01-secbase-hardening.conf` → `sshd -t` OK → reload. Both verified live.
**Scope/risk.** One trusted LAN host only. fail2ban + per-source penalties stay fully active for every
other source, including onboarding password brute-force from other LAN IPs. Root cause is client-side
(offer one key via `IdentitiesOnly=yes`); this only stops the operator's own host being throttled.
🔁 **Rollback.** Remove the IP from both files; `fail2ban-client reload`; `sshd -t && systemctl reload sshd`.

### D036 — `<second-admin>` passwordless (no-key) sudo, scoped ✅ IMPLEMENTED
✅ **What.** `<second-admin>` granted **passwordless, no-key** sudo SCOPED to the existing command-group
library (`PKG_MAINT, SYS_REBOOT, SVC_CTL, AUDIT_RUN, NET_INSPECT`) — `/etc/sudoers.d/20-<second-admin>`.
**Why.** Operator abandoned key-auth (agent-forward) sudo — **it does not function from the Git-Bash
client**, stated repeatedly. Chose passwordless-but-scoped over blanket NOPASSWD (least-privilege kept).
**How.** `<second-admin> ALL=(root) NOPASSWD: <aliases>`; validated isolated then `visudo -c`; mode 0440.
🔁 **Rollback.** `rm /etc/sudoers.d/20-<second-admin>`.

### D037 — `secbase-system-admins` passwordless admin role ✅⚠️ IMPLEMENTED
✅⚠️ **What.** New role group `secbase-system-admins`, **passwordless (NOPASSWD, no key)** sudo for new
command groups: `USER_ADMIN` (user/group mgmt), `DOCKER_ADMIN`, `PKG_INSTALL` (+`PKG_MAINT`),
`NET_ADMIN` (networking). Plus **RW to all of `/var/log`** via group ownership (`chmod 2775`, setgid).
**Why.** Operator wants a general admin role; passwordless per operator (key-auth sudo abandoned —
see D036). Capability list and both risk choices below were operator-selected.
⚠️ **Deviations / risks — owner-approved, explicit:**
- NOPASSWD on **root-equivalent** commands (`useradd`/`usermod`/`passwd`, `docker`, `dnf install`):
  members are effectively root-capable. Counter to least-privilege intent.
- `/var/log` group-writable: members can modify/delete any log incl. the 60-day audit trail and
  `sudo.log` → **weakens audit tamper-evidence.** Chosen over read-only / dedicated-dir options.
- "No SELinux mods" honored by **not granting** SELinux tooling (`setenforce`/`semanage`/`semodule`/
  `setsebool`/`chcon`) — verified blocked — but docker/pkg-install can reach root, so the boundary is
  **advisory, not enforced.**
**How.** 4 aliases added to `00-secbase-aliases`; grant `%secbase-system-admins ALL=(root) NOPASSWD:
USER_ADMIN, DOCKER_ADMIN, PKG_MAINT, PKG_INSTALL, NET_ADMIN` in `/etc/sudoers.d/30-secbase-system-admins`.
Snapshots in `configs-backup/`. Validated isolated + `visudo -c`. **Verified** (throwaway member):
in-scope cmds passwordless; `cat /etc/shadow` + `setenforce 0` blocked; `/var/log` write OK. **No members
assigned yet** — add with `usermod -aG secbase-system-admins <user>`.
🔁 **Rollback.** `rm /etc/sudoers.d/30-secbase-system-admins`; drop the 4 aliases from
`00-secbase-aliases`; `groupdel secbase-system-admins`; `chgrp root /var/log && chmod 755 /var/log`.

### D038 — `<second-admin>` BLANKET passwordless sudo (full root) ⚠️ IMPLEMENTED — owner override
⚠️ **What.** `<second-admin>` granted **`ALL=(ALL) NOPASSWD: ALL`** — full passwordless root, any command.
Replaces the scoped D036 grant in the same file `/etc/sudoers.d/20-<second-admin>`.
**Why.** Operator (`<owner>`) explicitly chose blanket over scoped on 2026-06-30, after being shown that
D036 was already working and that this **violates the CLAUDE.md non-negotiable "No blanket NOPASSWD:
ALL".** Owner-directed deviation, informed and on-record. Supersedes D036.
⚠️ **Risk.** <second-admin> = unrestricted root with no password challenge; includes SELinux tooling, shells,
`/etc/shadow`, everything. No least-privilege boundary remains for this account. Blast radius = full host.
**How.** Snapshot of prior D036 file → `configs-backup/sudoers.d/20-<second-admin>.20260630-blanket.bak`.
New file written, validated isolated (`visudo -cf`) then `visudo -c`, installed mode 0440 root:root.
**Verified.** `sudo -l -U <second-admin>` → `(ALL) NOPASSWD: ALL`. Reboot-safe (static sudoers drop-in).
🔁 **Rollback (restore scoped D036).** `install -m0440 -oroot -groot
configs-backup/sudoers.d/20-<second-admin>.20260630-blanket.bak /etc/sudoers.d/20-<second-admin> && visudo -c`.

---

## Deviation register (CIS L1)

| ID | Control | CIS expectation | This baseline | Justification |
|----|---------|-----------------|--------------|---------------|
| ⚠️D004 | SSH X11Forwarding | `no` | `yes` | Owner convenience tool; accepted risk |
| ⚠️D022 | SSH AgentForwarding | `no` | `yes` | Enables remote SSH-key sudo (pam_ssh_agent_auth); owner-approved |
| ⚠️D034 | SSH PasswordAuthentication | `no` (key-only) | `yes` **scoped** to group `onboarding` from LAN | Self-service first-key bootstrap; LAN-only, 10-day expiry, auto-revoked on promotion |
| ⚠️D037 | sudo NOPASSWD scope | no blanket NOPASSWD | passwordless **root-equivalent** cmds for `secbase-system-admins` | Owner-approved admin role; key-auth sudo abandoned (non-functional from client) |
| ⚠️D038 | sudo NOPASSWD scope | no blanket NOPASSWD | **`<second-admin> ALL=(ALL) NOPASSWD: ALL`** (full passwordless root) | **Direct owner override** of the non-negotiable, 2026-06-30; informed choice over working scoped D036 |
| ⚠️D037 | `/var/log` integrity | tamper-evident 60-day trail | **group-writable** (2775) to `secbase-system-admins` | Owner chose full RW over read-only/dedicated-dir |
| ⚠️D005 | mDNS/avahi | often disabled | **running, exposed** | Owner wants local mDNS discovery |
| ⚠️— | SSH exposed on LAN | restrict | `0.0.0.0:22` | Owner's intentional remote access (key-only) |
| ⚠️— | Central log server | required (L1 5.1) | local-only 60-day trail | No infra available; documented bypass |
| ⚠️D031 | Password max age (uid 1000) | ≤365 days | **never (`-M -1`)** | Operator account exempt from forced rotation; operator-managed |
| ⚠️D032 | Password complexity (uid 1000 current secret) | minlen14/minclass4 | accepted under temp `enforcing=0` | Operator's cloud-vault credential (not multi-host reuse); complexity enforced again for next change |

---

## Rollback index
- SSH: restore `audit/baseline/sshd_config.d.orig/` → `systemctl reload sshd`.
- Crypto policy: `update-crypto-policies --set DEFAULT`.
- DNS/resolved: restore prior `/etc/systemd/resolved.conf` (backed up in `configs-backup/`).
- sysctl: remove `/etc/sysctl.d/90-secbase-*.conf` → `sysctl --system`.
- sudo: remove `/etc/sudoers.d/*secbase*` and `10-agent` → policy reverts to wheel default.

---

## 2026-07-12 — DisplayLink USB monitor (evdi) enablement

**What:** Enable DisplayLink HSW USB display (`17e9:ff00`). In-kernel `udl` does not
support this chip (loads, no bind). Installed open-source `evdi` 1.15.0 (DKMS) + built
`libevdi`; proprietary `DisplayLinkManager` (Synaptics 6.3) pending operator download.

**Why:** External monitor output; device enumerates but no driver bound → dark.

**How:**
- `dnf install dkms kernel-devel-7.1.3-200.fc44 libdrm-devel`.
- evdi 1.15.0 from upstream git → `/usr/src/evdi-1.15.0` → `dkms build/install` (compiled
  clean on kernel 7.1.3, past upstream-verified 6.15).
- ⚠️ Secure Boot kept ENFORCING. DKMS auto-generated MOK (`/var/lib/dkms/mok.{key,pub}`),
  signed `evdi.ko` (sha512). `mokutil --import` staged; operator enrolls at console on
  reboot (one-time pw `evdi-enroll`).
- `/etc/modprobe.d/evdi.conf` (initial_device_count=4; softdep pre i915),
  `/etc/modules-load.d/evdi.conf` (autoload).
- ⚠️ Proprietary blob `DisplayLinkManager` — closed source. Operator downloads under
  Synaptics EULA; installs to `/opt/displaylink`, localhost-only daemon, no network bind.

**Deviation:** New out-of-tree signed kernel module + one proprietary userspace daemon.
MOK key is machine-local, self-signed, only trusts DKMS-built modules.

**Rollback:** `dkms remove evdi/1.15.0 --all`; `rm /etc/modprobe.d/evdi.conf
/etc/modules-load.d/evdi.conf /usr/src/evdi-1.15.0`; `mokutil --delete /var/lib/dkms/mok.pub`
(pw at reboot); remove `/opt/displaylink` + `displaylink.service` if installed.

## 2026-07-13 — DisplayLink: switch to COPR-managed (auto-updating)

**What:** Replaced the hand-built evdi with the Fedora COPR `crashdummy/Displaylink`
package (`displaylink-1.15.0-1`), so the driver auto-updates via dnf (rides 04:00 job).

**Why:** Operator wants ongoing driver updates ("subscribe"). Native apt-subscribe
impossible on Fedora; COPR = nearest dnf-native equivalent.

**How:**
- Retired manual DKMS evdi (`dkms remove evdi/1.15.0 --all`; removed `/usr/src/evdi-1.15.0`
  and manual `/etc/modprobe.d`,`/etc/modules-load.d` evdi confs — backed up in configs-backup).
- `dnf copr enable crashdummy/Displaylink` → `dnf install displaylink`.
- ⚠️ Third-party COPR added to trust surface (operator-approved). ⚠️ Proprietary
  `DisplayLinkManager` blob in `/opt/displaylink` (localhost-only; verified NO TCP bind).
- evdi still DKMS, auto-signed with the SAME enrolled MOK key (`1E:55:BE:...4C:93`) — no
  new key/enrollment. Loads under Secure Boot (still enforcing).
- Boot: udev `99-displaylink.rules` loads evdi + starts `displaylink-driver.service` on
  device plug. Verified: DVI-I-1-1 = 1920x1080@60 active, extended desktop.

**Deviation:** Non-distro COPR repo + proprietary userspace daemon. No network exposure.

**Rollback:** `dnf remove displaylink`; `dnf copr disable crashdummy/Displaylink`;
`dkms status` should show no evdi; module + /opt/displaylink removed by rpm erase.

### D039 — netmode egress switcher + default posture -> raw ⚠️🔁
**What:** New `scripts/netmode.sh` (→ `/usr/local/sbin/netmode`) unifies egress anonymity
backend switching behind one nftables table `inet secbase_net` + state `/etc/secbase/netmode.conf`,
persisted by `secbase-netmode.service`. Modes: `tor` (redirect all TCP→9040, supersedes legacy
`secbase_tor`/`secbase-tor-killswitch`), `lokinet` (L3 tun, drop-by-default), `nym` (redsocks→SOCKS5
1080), `raw` (direct). Optional `--wg` WireGuard wrap. All modes **fail-closed**; lo/LAN/backend-uid/
NTP always exempt so LAN SSH never drops.
**Why:** Owner wants to switch anonymity backend on demand (was Tor-only). i2p dropped (HTTP-outproxy
only, fragile); lokinet added instead (true transparent L3). Dead-man removed in favor of fail-closed
(management plane is LAN-exempt, so no remote-lockout risk).
**Switch performed:** default egress set to **raw** at owner request (2026-07-22). Legacy
`secbase-tor-killswitch.service` stopped+disabled, `secbase_tor` table deleted. Verified egress moved
from Tor exit → real ISP IP. dnscrypt DNS + firewalld plaintext-80/53 block remain (baseline).
**Deviation:** ⚠️ System no longer torified by default until `netmode tor` is re-run. Reboot comes up raw.
**Provisioning pending:** lokinet + nym need out-of-repo binaries (not in Fedora); `wireguard-tools`
+ `redsocks` install queued (dnf lock). WireGuard needs an owner-supplied `/etc/wireguard/NAME.conf`.
**Rollback:** `netmode tor` (re-arms transparent Tor). Full revert to legacy: `systemctl enable --now
secbase-tor-killswitch.service`. Snapshot: `configs-backup/netmode-20260722-180757/`.

### D040 — Kali VM on KVM/libvirt (sandboxed offensive tooling) ⚠️
**What:** Installed native virt stack (qemu-kvm 10.2.2, libvirt 12, virt-install/manager/viewer,
edk2-ovmf) and imported Kali 2026.2 prebuilt qcow2 as libvirt domain `kali-linux-2026.2`
(4 GiB RAM, 2 vCPU host-passthrough, virtio disk/NIC). Image SHA256-verified against Kali
`SHA256SUMS` before import (c7c35588…6bd071). Disk at `/var/lib/libvirt/images/`, relabeled
`virt_image_t`, owned qemu:qemu. Guest network stance controlled by
`scripts/kali-netmode.sh {nat|isolated|mirrored}`.
**Why:** Owner wants Kali (CLI + windowed) without polluting the hardened host baseline. VM =
SELinux-sVirt-confined sandbox; offensive tools never touch host userspace.
**How / posture:**
- SPICE graphics `listen=none` → **local Unix socket only, NO TCP bind** (verified: no qemu
  listener). GUI via `virt-viewer --attach` / virt-manager over the libvirt socket. Aligns
  localhost-only rule.
- sVirt per-VM MCS confinement (SELinux still Enforcing). KVM nested=on.
- Default stance **NAT** (virbr0 192.168.122.0/24, guest lease .239) — outbound only, no new
  host port exposed. dnsmasq on virbr0 is standard libvirt (bound to the virtual bridge).
- `kali-netmode.sh` also offers `isolated` (10.199.0.0/24, no forward = airgapped) and
  `mirrored` (macvtap bridge = LAN peer). Applies --live+--config, validates before detaching.
- Least privilege: `<owner>` added to `libvirt`+`kvm` groups (manage VMs w/o root). No sudo change.
**Deviation:** ⚠️ `mirrored` mode needs a WIRED uplink; script REFUSES over WiFi (current uplink
wlp1s0 is wireless — 802.11 rejects foreign source MACs). NAT/isolated unaffected.
**Reboot survival:** libvirtd enabled; `default` net autostart=yes. Domain does NOT autostart
(manual boot by design). qcow2 on LUKS root (encrypted at rest).
**Rollback:** `virsh destroy kali-linux-2026.2; virsh undefine kali-linux-2026.2 --nvram`;
`rm /var/lib/libvirt/images/kali-linux-2026.2.qcow2`; `dnf remove qemu-kvm libvirt virt-*`.
Snapshot: `configs-backup/virt-20260722/`.

### D041 — `<owner>` BLANKET passwordless sudo (full root) ⚠️ IMPLEMENTED — owner override
⚠️ **What.** `<owner>` granted **`ALL=(ALL) NOPASSWD: ALL`** in new file `/etc/sudoers.d/21-<owner>` —
full passwordless root, any command. Additive to existing `wheel` + key-auth sudo (pam_ssh_agent_auth,
<owner>.pub); this line makes sudo require no auth at all.
**Why.** Operator (`<owner>`) explicitly directed "set me up exactly similar to <second-admin>" on 2026-07-23,
after being shown <owner> already had key-authenticated (passwordless-via-key) sudo and that blanket
NOPASSWD **violates the CLAUDE.md non-negotiable "No blanket NOPASSWD: ALL".** Owner-directed
deviation, informed and on-record. Mirrors D038 (<second-admin>).
⚠️ **Risk.** <owner> = unrestricted root with no password/key challenge; includes SELinux tooling, shells,
`/etc/shadow`, everything. No least-privilege boundary remains for this account. Blast radius = full host.
**How.** New drop-in (no prior file to snapshot). Written to temp, validated isolated (`visudo -cf`)
then full `visudo -c`, installed mode 0440 root:root as `/etc/sudoers.d/21-<owner>`.
**Verified.** `sudo -l -U <owner>` → `(ALL) NOPASSWD: ALL`. Reboot-safe (static sudoers drop-in).
🔁 **Rollback.** `rm /etc/sudoers.d/21-<owner> && visudo -c` (<owner> retains wheel + key-based sudo).

### D042 — Google Chrome installed for desktop use (owner request)
**What.** `google-chrome-stable-150.0.7871.186` installed from the owner-supplied
`google-chrome-stable_current_x86_64.rpm` (Fedora native pkg; the two `.deb` files ignored).
**Why.** Owner requested Chrome for the <owner> desktop session. `dnf` chosen over raw `rpm` so the
vendor repo `/etc/yum.repos.d/google-chrome.repo` (enabled=1, gpgcheck=1) is wired for auto-updates,
consistent with the daily 04:00 update job.
**How.** `dnf install -y <rpm>`. %post repo-key import warned (rpm-lock contention during scriptlet)
but package + repo installed cleanly.
🔁 **Rollback.** `dnf remove -y google-chrome-stable && rm -f /etc/yum.repos.d/google-chrome.repo`.

### D043 — Firefox (<owner>) legacy-device TLS/HTTP relaxation ⚠️ IMPLEMENTED — owner override
**What.** `user.js` in <owner>'s default Firefox profile relaxes browser crypto for legacy LAN gear:
TLS floor lowered to **TLS 1.0** (+enable-deprecated), 3DES/weak ciphers re-enabled, SHA-1 certs
allowed, cert-pinning + HSTS-preload off, HTTPS-Only mode off, mixed-content + insecure-form
warnings off. File: `~/.config/mozilla/firefox/rlphwstg.default-release/user.js`.
**Why.** Owner (`<owner>`) directed unconditional access to a legacy switch web UI that only speaks
old HTTP/TLS. Deviates from the hardening baseline (weakens TLS posture for ALL sites in this
profile, not just the switch). Informed, owner-directed, on-record.
⚠️ **Risk.** Applies browser-wide, not per-site: any site this profile visits can now negotiate
TLS 1.0/1.1, 3DES, and SHA-1 certs → downgrade/MITM exposure on untrusted networks. Mitigated only
by the fact that hardened use is LAN/admin. Consider a separate profile for general browsing.
**Limits (not fixable by prefs).** SSLv3/SSLv2 are removed from Firefox — an SSLv3-only device still
won't connect (needs an stunnel localhost bridge). Self-signed certs still require a one-time
per-host "Accept the Risk and Continue" click.
**How.** `user.js` (overrides prefs.js every startup). Takes effect after a full Firefox restart.
🔁 **Rollback.** `rm ~/.config/mozilla/firefox/rlphwstg.default-release/user.js` and restart Firefox.

### D044 — Reverse-proxy container published on all interfaces (0.0.0.0:443 + 0.0.0.0:8080) ⚠️ owner override
**What.** A dockerized nginx reverse proxy (`agentic-proxy-agentic-01`, image `nginx:stable`) is
published on **all interfaces**: `0.0.0.0:443` (HTTPS, self-signed edge TLS) and `0.0.0.0:8080`
(HTTP, 301-redirects to :443). Built/managed by `/root/VMs_and_Docker/agentic_proxy/`.
**Why.** Owner explicitly chose LAN exposure (`--bind 0.0.0.0`) for this proxy on 2026-07-23.
Deviates from the CLAUDE.md non-negotiable **"Localhost-only by default"** (approved intentional
exceptions were SSH/22 and mDNS/5353 only). Informed, owner-directed, on-record.
⚠️ **Risk.** Adds two LAN-reachable listeners beyond the approved exception set. TLS is self-signed
(no trusted chain; clients must accept the cert). The proxy is hardened (server_tokens off, method
allow-list, per-IP rate/conn limits, dotfile deny, security headers + HSTS) and key-free, but any
LAN host can now reach it. Note: host nftables still governs actual reachability — inbound to the
published ports transits Docker's DNAT/forward path, not host INPUT; no host firewall rule was added
or changed by this decision.
**How.** `nginx_proxy_builder.py create agentic-01 --listen 8080 --tls --https-port 443 --bind
0.0.0.0 --mode whitehat --capture full`. Config validated (`nginx -t`) before start. Full
request/response body capture is on (njs); the Authorization header is never logged.
**Verified.** `ss -ltn` → `0.0.0.0:443` and `0.0.0.0:8080` LISTEN; HTTPS `/healthz` → `ok`; HTTP
:8080 → `301 https://…:443/`; HSTS + security headers present on proxied/placeholder responses.
🔁 **Rollback.** `python /root/VMs_and_Docker/agentic_proxy/nginx_proxy_builder.py teardown
agentic-01` (removes container, network, files). To keep it but revert to loopback-only: re-create
with `--bind 127.0.0.1` and `up`.

### D043b — Firefox global TLS relaxation ROLLED BACK
The D043 profile-wide `user.js` was removed at owner request (it weakened TLS for ALL sites, not
just the switch). Firefox restored to hardened posture. Superseded by D044 (scoped bridge).

### D044 — stunnel legacy-switch TLS bridge (scoped, loopback) ✅ IMPLEMENTED
**What.** systemd service `stunnel-legacy` bridges legacy switch web UIs without weakening any
browser. Browser speaks MODERN TLS to `127.0.0.1`; stunnel speaks legacy **TLS 1.0** (SECLEVEL=0,
LEGACY_SERVER_CONNECT, unsafe-legacy-renegotiation) to the switch.
- Switch A `<mgmt-ip-a>:443`  ->  `https://127.0.0.1:8017`
- Switch B `<mgmt-ip-b>:443`  ->  `https://127.0.0.1:8019` (device currently down; bridge ready)
Files: `/etc/stunnel/legacy-switch.conf`, `/etc/stunnel/legacy-front.pem` (modern self-signed,
CN/SAN=127.0.0.1, root 0600), `/etc/systemd/system/stunnel-legacy.service`.
**Why.** Owner needs to manage two legacy switches that only speak TLS 1.0 w/ legacy renegotiation.
Replaces the rejected global Firefox weakening (D043) — legacy crypto is now confined to the
stunnel<->switch hop for these two internal IPs only. Probe findings: .17 = TLS1.0-only, requires
legacy renegotiation; Fedora system crypto-policy (DEFAULT, MinProtocol=TLSv1.2) blocks direct
browser/curl access, which the per-tunnel stunnel overrides cleanly.
**Scope/exposure.** All 4 listeners bound to 127.0.0.1 ONLY (loopback) — compliant with the
localhost-only rule; nothing new exposed on the LAN. No system crypto-policy change. Browser stays
fully hardened.
**Verified.** `systemctl is-active` = active, enabled at boot (reboot-safe). `curl https://127.0.0.1:8017`
-> HTTP 200 switch auth page (2 redirects). .19 -> unreachable (device off), bridge waits.
**Caveat.** Browser shows a ONE-TIME self-signed-cert exception for the modern localhost cert
(`legacy-front.pem`) — normal, safe; can be removed by importing that cert into the FF/NSS trust store.
🔁 **Rollback.** `systemctl disable --now stunnel-legacy && rm /etc/systemd/system/stunnel-legacy.service
/etc/stunnel/legacy-switch.conf /etc/stunnel/legacy-front.pem && systemctl daemon-reload`.

### D045 — stunnel legacy-switch bridge REMOVED (device moved to HTTP)
Owner reconfigured the switches to HTTP-only, so the D044 bridge is obsolete. Removed service,
config, and cert (`stunnel-legacy.service`, `/etc/stunnel/legacy-switch.conf`, `legacy-front.pem`).
Desktop/menu launchers repointed to direct `http://<mgmt-ip-a>` / `http://<mgmt-ip-b>`.
No listeners remain; hardened posture fully restored (no legacy TLS anywhere).

### D046 — Scoped outbound HTTP exception for lab switch subnets ✅ IMPLEMENTED
**What.** Added firewalld direct ACCEPT rules (priority 0, before the priority-1 reject) allowing
outbound `tcp dport 80` to internal lab nets only: `<mgmt-cidr>`, `10.0.1.0/24`, `10.0.2.0/24`.
**Why.** The hardening baseline rejects ALL cleartext HTTP egress (`OUTPUT -p tcp --dport 80 REJECT
--reject-with tcp-reset`). That reset masqueraded as "switch not serving HTTP" and blocked the owner
from reaching Netgear switch web UIs (GoAhead-Webs) at <mgmt-ip-a>/.19. Owner-directed scoped hole.
**Scope.** IPv4 only, these 3 internal subnets, port 80 only. Global HTTP reject + DNS reject + all
IPv6 rejects remain intact for everything else. Loopback-only posture unchanged.
**How.** `firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -p tcp -d <net> --dport 80
-j ACCEPT` x3, then `--reload`. Snapshot: `configs-backup/nftables/ruleset.20260723-212929.bak`.
**Verified.** `curl http://<mgmt-ip-a>` & `.19` -> HTTP 200 (GoAhead-Webs). Accept counters incrementing;
reject counter flat for switch traffic. Persisted in `/etc/firewalld/direct.xml` (reboot-safe).
🔁 **Rollback.** `firewall-cmd --permanent --direct --remove-rule ipv4 filter OUTPUT 0 -p tcp -d <net>
--dport 80 -j ACCEPT` for each net, then `--reload`.

### D047 — agentic_proxy PoC migrated from rootful → rootless Docker ✅ IMPLEMENTED
**What.** Moved the `agentic_proxy` lab PoC (project 001) off the rootful system Docker daemon onto a
**rootless** daemon running as the unprivileged owner account `<owner>` (uid 1000). Disabled the rootful
daemon. Both proxy instances (`agentic-01` HTTPS-capture on 443; `fwd` HTTPS-CONNECT forward proxy on
8888) verified running under rootless.
**Why.** Aligns the PoC's *own* runtime with the project's containment thesis and the  brain-account
model: an autonomous coding/ops agent should not run as root/owner. Rootless Docker removes the
`docker`-group-equals-root escalation path. Owner-directed ("move to rootless; no rootful docker").
**Host changes (all persistent):**
1. Installed `slirp4netns` (1.3.1) + `fuse-overlayfs`; `loginctl enable-linger <owner>`.
2. **Privileged port 443:** `sysctl net.ipv4.ip_unprivileged_port_start=443`, persisted in
   `/etc/sysctl.d/99-secbase-rootless-lowport.conf`. NOTE: this lets any unprivileged process bind
   443–1023 host-wide (accepted; single-user dev host). Rejected alternative: `setcap
   cap_net_bind_service` on `slirp4netns`/`rootlesskit` — it **breaks** their network-namespace
   operations ("failed to restore thread's network namespace"). Do not use setcap here.
3. **Source-IP fidelity:** pinned RootlessKit port driver to slirp4netns —
   `DOCKERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER=slirp4netns` in
   `~<owner>/.config/systemd/user/docker.service.d/override.conf`. The default `builtin` driver SNATs
   every client to one internal address. Verified: `agentic-01` logged the real LAN client IP
   `<host-ip>`, not a gateway address.
4. **Container DNS:** only slirp's resolver `10.0.2.3` is reachable from rootless containers (all
   external DNS unreachable); set `~<owner>/.config/docker/daemon.json` → `"dns": ["10.0.2.3"]`. The `fwd`
   proxy's nginx `resolver` set to `127.0.0.11` (Docker embedded DNS → forwards to 10.0.2.3), ipv6 off.
5. **`--connect` source build under rootless:** failed on `apt` because rootless egress is IPv4-only and
   **D046's firewall rejects all outbound cleartext port 80**, so Debian's http mirrors were
   unreachable. Fixed in the tool's connect Dockerfile: `Acquire::ForceIPv4` + rewrite apt sources to
   **https** (git/wget already 443). This *conforms to* the D046 no-cleartext-egress posture rather than
   working around it.
6. Disabled rootful daemon: `systemctl disable --now docker.service docker.socket` (both inactive).
**Verified.** rootless daemon `active` (`SecurityOptions` includes `name=rootless`); `agentic-01`
443→200; `fwd` 8888 healthz→200 and CONNECT to `https://example.com/`→200; rootful daemon inactive.
🔁 **Rollback.** `systemctl enable --now docker.service docker.socket` (rootful back); stop <owner>
rootless (`systemctl --user stop docker`); optionally revert the sysctl drop-in, `daemon.json`, and the
port-driver override. The setcap removals and package installs are inert to leave in place.

### D048 — Git signing key passphrase removed (passwordless commit/tag signing) ⚠️🔁 owner request
**Date.** 2026-07-24.
**What.** Removed the passphrase from OpenPGP signing key `<signing-key-id>` (RSA4096 [SC], uid `<owner> <owner-email>`). Key now unlocks with no passphrase.
**Why.** `commit.gpgsign=true`+`tag.gpgsign=true` made every git commit/tag prompt for the passphrase,
including Claude Code's launch-time checkpoint commits. Owner wants signing kept ON but with zero
prompts. Passphrase removal is the only reboot-safe way to never prompt (agent-cache TTL re-prompts
after the daily 04:30 reboot).
**Not junk.** Verified NO SSH/GPG cross-wiring existed: `gpg.format` unset (openpgp), `sshcontrol`
empty, no `enable-ssh-support`; `SSH_AUTH_SOCK` is a normal ssh-agent. The feared "GPG-signing-key-as-
SSH-key" mixup was never present. Nothing undone.
**How.** `gpg --edit-key <signing-key-id> passwd` → empty new passphrase (loopback, warm agent cache).
Git signing config unchanged (still on).
**Residual risk.** Signing private key now sits on disk with NO passphrase. Protected at rest only by
LUKS FDE + `~/.gnupg` `0600` perms + single-user host. Accepted per owner. NOTE: anyone with live
read access to `~<owner>/.gnupg` can sign as the owner — key is no longer a two-factor (have+know) secret.
**Verified.** Cold agent (`gpgconf --kill gpg-agent`) + `--pinentry-mode error`: clearsign OK; temp-repo
`git commit` produced Good signature, no prompt.
**Snapshot.** Pre-change key + git config backed up: `/home/<owner>/secbase-standard/configs-backup/gpg-signing-20260724-180818` (root `0700`).
🔁 **Rollback.** Re-add a passphrase: `gpg --edit-key <signing-key-id> passwd` (set new passphrase, save).
To restore the exact prior key: `gpg --import /home/<owner>/secbase-standard/configs-backup/gpg-signing-20260724-180818/secret-key-<signing-key-id>.asc`. To stop signing
entirely instead: `git config --global commit.gpgsign false && git config --global tag.gpgsign false`.

### D049 — Baseline tree chowned to `<owner>` + replicated to second host ⚠️🔁 owner request
**Date.** 2026-07-24.
**What.** Two changes. (1) `chown -R <owner>:<owner> /home/<owner>/secbase-standard/` — the whole
baseline tree (694 paths) was `root:root`; it is now owner-owned. (2) Copied the tree (102M, 691 files)
to `<owner>@<peer-ip>:~/secbase-standard/` over key-only SSH.
**Why.** Owner wants a working copy of the baseline on the second host and instructed the local tree be
chowned first. Prior state made ~96M (all of `exports/`, `HANDOFF.md`, most `scripts/`, `audit/baseline/`,
`configs-backup/*`) unreadable to `<owner>`, so no unprivileged copy was possible.
**Excluded from transfer** (owner decision — key material stays on this host only):
`configs-backup/gpg-signing-*/` (contains D048's exported secret key `<signing-key-id>.asc`) and
`configs-backup/sudoers.d/`. Verified absent on the remote.
**How.** `tar -cf - --exclude=... . | ssh <owner>@<peer-ip> 'tar -C secbase-standard -xpf -'`.
Modes preserved; remote ownership is `<owner>` (unprivileged extraction cannot restore root).
**Residual risk.** The 60-day audit trail (`exports/`), boot-state baselines (`audit/baseline/`, incl.
`sshd_config.orig`) and replaced configs are no longer root-gated locally — any process running as
`<owner>` can now read and modify them, including tampering with the audit evidence. Modes are unchanged
(e.g. `exports/*.tar.gz` stay `0600`, `gpg-signing-*/` stays `0700`) so non-owner accounts are still
excluded; the loss is the root/owner boundary only. A second full copy of the baseline (minus key
material) now exists on <peer-ip> under that host's own protections. Accepted per owner.
**Snapshot.** Exact pre-change owner/group/mode of all 736 paths recorded at
`configs-backup/ownership-pre-chown-20260724T222111Z.txt`.
**Verified.** Local and remote path manifests and full content checksums identical
(`md5sum` of sorted per-file `md5sum` → `<checksum>` both sides); 691 files, 102M each.
🔁 **Rollback.** Every path was `root:root` pre-change, so:
`sudo chown -R root:root /home/<owner>/secbase-standard/`.
Exact per-path restore (owner + mode) from the manifest:
`while read -r og mode p; do sudo chown "$og" "$p"; sudo chmod "$mode" "$p"; done < configs-backup/ownership-pre-chown-20260724T222111Z.txt`
Remote copy: `ssh <owner>@<peer-ip> 'rm -rf ~/secbase-standard'`.
