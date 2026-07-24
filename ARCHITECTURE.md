---
type: Architecture
title: Architecture — Secure Hardening Baseline
description: How the controls compose — design principles, identity and privilege model, network exposure, DNS and Tor chain, host hardening, and recovery invariants.
tags: [architecture, identity, sudo, ssh, dns, tor, network-exposure, selinux]
status: stable
stale_after: 2027-01-24
generated:
  by: claude-code/opus-5
  at: 2026-07-24T19:01:22-04:00
sources:
  - resource: /DECISIONS.md
    title: Dated rationale for every element described here
---

# Secure Hardening Baseline — Architecture

A current, security- and anonymity-focused hardening baseline for a systemd Linux host.
Target: **CIS Level 1** plus additional enterprise controls. This document records the security
choices and how they fit together. Companions: `CONTROLS.md` (what to apply) and `DECISIONS.md`
(the dated rationale log).

**Foundation assumed in place:** UEFI boot, Secure Boot, full-disk encryption (LUKS) with TPM2
auto-unlock and a retained passphrase keyslot, SELinux/MAC enforcing.

---

## 1. Design principles

1. **Least privilege.** No account or service gets more than it needs. No blanket
   `NOPASSWD: ALL`. Privilege is delineated by group and by command.
2. **Key as the universal credential.** Humans and automated agents authenticate with SSH keys —
   for login and (where applicable) for escalation. No typed passwords in the automation path.
3. **Localhost-only by default.** No service listens on a non-loopback interface without a
   documented decision. Intentional exceptions: SSH (22) and mDNS (5353).
4. **On-path/MITM resistance.** Encrypted + validated DNS, no LLMNR, no ICMP redirects / source
   routing / rogue RAs, ARP hardening, gateway MAC pinning, ARP-anomaly detection.
5. **Encrypted egress only.** Outbound plaintext HTTP (80) and plaintext DNS (53) are rejected.
6. **Anonymity-aware DNS.** Queries are spread across a randomized pool of no-logging encrypted
   resolvers so no single operator can profile all lookups.
7. **Durable local audit.** No external log server assumed; a local 60-day state trail plus 30-day
   log exports, with snapshots at boot and daily.
8. **Reboot survivability.** Unattended daily update + reboot; every control returns after reboot.
9. **Recoverability preserved.** Physical console, disk passphrase keyslot, existing SSH key, and
   MAC-enforcing are never removed.

---

## 2. Identity & privilege model

| Class | Login shell | SSH login | sudo |
|-------|-------------|-----------|------|
| Primary user | `/bin/bash` | yes (key-only) | authenticated, scoped |
| Admin user (`<owner>`) | `/bin/bash` | yes (key-only) | `ALL` via `wheel`; password fallback (key-auth sudo unused — see note) |
| Secondary admin | `/bin/bash` | yes (key-only) | passwordless **scoped NOPASSWD** (D036) |
| System-admin role (`secbase-system-admins`) | `/bin/bash` | yes (key-only) | passwordless **NOPASSWD**, scoped admin cmd-groups (D037); `/var/log` rw |
| Onboarding user | `/bin/bash` | LAN-only password (temp, 10-day) → key after promotion | none until auto-promoted |
| Remote-capable agent | `/bin/bash` | loopback/remote (key-only) | scoped |
| Local service agent | `nologin` | none | NOPASSWD, narrow command whitelist |

**Agent provisioning (standard process).** Each agent is a key-bearing identity. A reusable
provisioner creates the account, generates an ed25519 key, self-enrols the public key (loopback
`ssh-copy-id` pattern for remote-capable agents; escalation key-store for all), and joins the
appropriate group. One key per agent, used for both SSH and escalation — uniform across remote
users and headless service accounts.

**Self-service onboarding (humans).** Since the host is key-only, a *first* key can't be installed
by `ssh-copy-id` (no password to auth with). The `onboarding` group bridges this: `secbase-onboard
<user>` creates the account with a 10-day temp password and a scoped sshd exception
(`Match Group onboarding Address <LAN>/24` → `PasswordAuthentication yes`; global key-only is
unchanged for everyone else). The user logs in once over the LAN, `ssh-copy-id`s their key, and a
templated systemd path-unit (`secbase-promote@<user>`) fires: it copies the login key into the sudo
key-store, adds `wheel`, drops `onboarding` (revoking password auth), and normalises password aging.
Net result is a key-only-login `wheel` account (its key also enrolled in the sudo key-store). The
10-day window is scoped to onboarding accounts only; the global `useradd`/`login.defs` default stays
365 so the operator/root recovery passwords never expire. See D033/D034.

**Operative sudo reality (IMPORTANT).** Agent-forwarded key-auth sudo (D008 `pam_ssh_agent_auth`)
depends on the *client* forwarding an agent that holds the right key; on clients where that is not
reliable it is effectively unusable. The password fallback remains, but the dependable passwordless
path is **scoped `NOPASSWD`** roles: a secondary admin account (D036) and the
`secbase-system-admins` group (D037, which also gets group-writable `/var/log`). New no-key admin
roles are built as `Cmnd_Alias` groups + a group grant — never blanket `NOPASSWD: ALL`.

> Deployment note: verify agent-forward key-auth sudo end-to-end from *your* client before relying
> on it. If it does not work, use the scoped-`NOPASSWD` role path and leave the PAM rule in place
> with its password fallback.

**sudo delineation** (`/etc/sudoers.d/`, each `visudo`-validated):
- Command groups via `Cmnd_Alias` (package maintenance, reboot, service control, audit,
  read-only network inspection).
- Service agent account: `NOPASSWD` for the maintenance/reboot/audit aliases only — the nologin
  account isolation plus the command whitelist are the security boundary.
- Operators group: interactive, authenticated (not passwordless), scoped to service control +
  inspection + audit.
- `use_pty` and a dedicated sudo log are enforced.

**Sudo authentication = SSH key (no typed password).** `pam_ssh_agent_auth` is the first `auth`
rule in `/etc/pam.d/sudo` (`sufficient`); it verifies the caller's SSH-agent key against a per-caller
store `/etc/security/sudo_authorized_keys.d/%u.pub`, with the password stack retained below as
fallback (no lockout). `SSH_AUTH_SOCK` is preserved via `env_keep`. The module is built from a
GPG-verified upstream distro source and vendored for reproducibility; the installer rebuilds it and
degrades safely if the build fails. Authentication (key possession) is thus separate from
authorization (the `Cmnd_Alias` role groups above).

---

## 3. Network exposure

| Port | Service | Bind | Status |
|------|---------|------|--------|
| 22/tcp | SSH | all | exposed (intentional), key-only |
| 5353/udp | mDNS | all | exposed (intentional), local discovery |
| 53 | resolver stub | loopback | local only |
| 5355 | LLMNR | — | disabled (poisoning vector) |
| — | libvirt SPICE | local unix socket | VM console, no TCP bind |
| 67/53 | dnsmasq | virbr0 (192.168.122.1) | VM-only NAT net, off host NICs |

**DNS chain:** resolver stub → local `dnscrypt-proxy` → randomized pool of no-log,
DNSSEC-validating, encrypted (DoH/DNSCrypt over 443) resolvers. `lb_strategy=random`,
`require_nolog`, `require_dnssec`. ISP/DHCP DNS overridden.

**Egress:** plaintext HTTP (80/tcp) and plaintext DNS (53 udp+tcp) rejected; loopback exempt.

**Anti-MITM:** reverse-path filtering; no redirect accept/send; no source routing; ARP
ignore/announce hardening; martian logging; no IPv6 RA. Gateway MAC pinned per network
(trust-on-first-connect, permanent ARP entry); arpwatch logs ARP anomalies. fail2ban bans SSH
brute force.

**Outbound anonymity:** Tor with North-America-locked exits (`ExitNodes {us},{ca}`, `StrictNodes 1`),
standard 3-relay circuit. **Transparent system-wide torification is active** — an nftables table
redirects all outbound TCP into Tor's TransPort, with exemptions for loopback, the tor user, the
LAN + established connections (preserves the admin SSH session), and NTP (Tor can't carry UDP and
needs an accurate clock); non-Tor UDP/ICMP to the internet is dropped to prevent leaks. Encrypted
DNS rides Tor over TCP (dnscrypt `force_tcp`). Enabled via a boot-time unit after Tor; on a live
remote host the switch is flipped behind a systemd dead-man auto-revert and only kept after a plain
`curl` is confirmed to return a Tor exit IP with the SSH session still up.

**Virtualization sandbox:** KVM/libvirt hosts guest VMs for tooling that should not run on the
host, isolated from it by SELinux sVirt (per-VM MCS). Graphics = SPICE on a local unix socket (no
TCP). Guest egress stance is one of: **NAT** (default, outbound-only via `virbr0`), **isolated**
(airgapped, no forwarding), or **mirrored** (LAN peer, wired uplink only). See D040. Guest traffic
exits the host through whatever `netmode` (D039) backend is active.

---

## 4. Host hardening (CIS L1)

- SSH: key-only, no root login, `MaxAuthTries 4`, `LoginGraceTime 60`, idle timeout, no agent/TCP
  forwarding, verbose logging, no banner. Modern SSH algorithms pinned explicitly (chacha20/AES-GCM,
  SHA-2-ETM MACs, curve25519/sntrup KEX). System crypto policy is **DEFAULT**, not FUTURE: FUTURE
  rejects RSA-2048 certificate chains (Let's Encrypt + much of the web) and breaks normal HTTPS and
  updates; DEFAULT is still strong (TLS1.2+, no SHA-1 sigs, no weak ciphers) and SSH is hardened
  independently via the pinned algorithms.
- Kernel sysctl: ASLR, `kptr_restrict`, `dmesg_restrict`, `ptrace_scope`, `suid_dumpable=0`,
  protected hardlinks/symlinks/fifos/regular, restricted BPF, `perf_event_paranoid`.
- Unused filesystems and rare network protocols blacklisted via modprobe.
- Core dumps disabled. `umask 027`. Password aging + quality (minlen 14, 4 classes). Account
  lockout via faillock. cron/at restricted to root.
- auditd baseline rules (identity, sudoers, sshd, sysctl, sessions, privilege escalation).
- AIDE file-integrity database.

**Documented deviations** (see decision log): X11 forwarding retained (usability); mDNS running
and exposed (local discovery); SSH exposed on the LAN (key-only); no central log server (local
trail instead); usb-storage left enabled (workstation use).

---

## 5. Maintenance & resilience

- Daily refresh + upgrade (logged), then guarded daily reboot.
- State snapshot at every boot and daily (60-day retention); dated log exports (30-day retention).
- All controls persist via `sysctl.d` / `sshd_config.d` / systemd units / permanent firewall
  rules, so the host returns hardened after each reboot.

---

## 6. Recovery invariants (never remove)

Physical console login · disk-encryption passphrase keyslot · existing SSH key · MAC enforcing.
Replaced configs are backed up under `configs-backup/` and `audit/baseline/` inside the host's own
config corpus (`/root/<hostname>/`, see `README.md`) — never in this repository.
