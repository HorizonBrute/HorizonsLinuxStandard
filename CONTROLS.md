---
type: Control Set
title: Controls — Secure Linux Desktop Standard
description: Prescriptive, ordered control list for hardening a Fedora workstation to CIS Level 1 plus enterprise controls, with verification for each.
tags: [fedora, cis-level-1, hardening, ssh, sudo, dns, firewall, tor, auditd, selinux]
status: stable
stale_after: 2027-01-24
generated:
  by: claude-code/opus-5
  at: 2026-07-24T19:01:22-04:00
sources:
  - resource: /DECISIONS.md
    title: Dated rationale log this control set is distilled from
  - resource: /ARCHITECTURE.md
    title: How the controls compose
---

# Controls

Apply in the order given. The order is deliberate: each control's recovery path exists before the
control that could remove it. `D###` refers to the entry in [DECISIONS.md](DECISIONS.md) carrying
the full rationale, alternatives rejected, and rollback.

**Before anything:** capture the baseline snapshot (`README.md` §2). Several controls are not
safely reversible without it.

**Legend:** ⚠️ = can lock you out; keep a console session open. 🔁 = rollback documented in the log.

---

## C1 — Identity & privilege model

| # | Control | Why | Ref |
|---|---|---|---|
| C1.1 | No blanket `NOPASSWD: ALL`. Privilege is scoped by `Cmnd_Alias` group + group grant. | The command whitelist *is* the security boundary for unattended automation. | D001, D007 |
| C1.2 | Automated agents get a dedicated non-login (`nologin`) service account, never a human's. | Account isolation + command whitelist; no shell to hijack. | D001, D020 |
| C1.3 | Each agent is a key-bearing identity: one ed25519 key, used for both SSH and escalation. | Uniform credential; revocation is one key removal. | D007 |
| C1.4 | Sudo: `use_pty` and a dedicated sudo log enabled. | Defeats TTY-hijack; produces an escalation trail. | D001 |
| C1.5 | Second admin account mirroring the primary, key-only. | Recovery path when the primary account is broken or locked. | D033 |

Verify: `sudo -l -U <account>` shows only the intended aliases; `getent passwd <agent>` shows
`nologin`; `visudo -c` clean.

---

## C2 — SSH ⚠️

| # | Control | Why | Ref |
|---|---|---|---|
| C2.1 | Key-only auth: `PasswordAuthentication no`, `PermitRootLogin no`. | Removes brute-forceable credential entirely. | D004 |
| C2.2 | `MaxAuthTries 4`, `LoginGraceTime 60`, idle timeout set. | CIS L1; bounds brute force and abandoned sessions. | D004 |
| C2.3 | Pin modern algorithms explicitly — chacha20-poly1305 / AES-GCM ciphers, SHA-2 ETM MACs, curve25519 + sntrup761 KEX. | Hardens SSH independently of system crypto policy. | D004, D019 |
| C2.4 | System crypto policy stays **DEFAULT**, not FUTURE. | FUTURE rejects RSA-2048 chains — breaks Let's Encrypt, most HTTPS, and `dnf`. DEFAULT is still TLS1.2+, no SHA-1 sigs, no weak ciphers. | D019 |
| C2.5 | Verbose SSH logging; no banner. | Auth trail for fail2ban and audit. | D004 |
| C2.6 | Disable TCP forwarding; agent forwarding only if key-auth sudo is actually used. | Forwarded agents are a lateral-movement vector — enable deliberately, not by default. | D022 |

**Validate `sshd -t` before every restart, with a second authenticated session open.** This is the
single most common lockout.

Verify: `sshd -T | grep -E 'permitrootlogin|passwordauthentication|maxauthtries'`.

---

## C3 — Sudo authentication by SSH key

| # | Control | Why | Ref |
|---|---|---|---|
| C3.1 | `pam_ssh_agent_auth` as first `auth` rule in `/etc/pam.d/sudo`, `sufficient`, password stack retained below. | Key possession replaces typed passwords; fallback prevents lockout. | D008 |
| C3.2 | Per-caller key store at `/etc/security/sudo_authorized_keys.d/%u.pub`, root-owned. | Authorization data must not be writable by the caller it authorizes. | D008 |
| C3.3 | `SSH_AUTH_SOCK` preserved via `env_keep`. | Without it the module cannot see the agent. | D008 |
| C3.4 | Build the module from GPG-verified upstream source and vendor it; installer degrades safely if the build fails. | Not packaged by Fedora/EPEL — provenance must be established, not assumed. See `vendor/pam_ssh_agent_auth/PROVENANCE.md`. | D008 |

> **Verify end-to-end from your own client before relying on this.** Agent-forwarded key-auth sudo
> depends on the client forwarding an agent holding the right key; on clients where that is
> unreliable, use scoped `NOPASSWD` roles (C1.1) instead and leave this rule in place with its
> password fallback. Do not remove the fallback. (D008, D036, D037)

---

## C4 — Kernel & module hardening (CIS L1)

| # | Control | Why | Ref |
|---|---|---|---|
| C4.1 | sysctl: ASLR on, `kptr_restrict`, `dmesg_restrict`, `ptrace_scope`, `suid_dumpable=0`, protected hardlinks/symlinks/fifos/regular, restricted BPF, `perf_event_paranoid`. | Removes the standard local-privesc primitives. | D017 |
| C4.2 | Blacklist unused filesystems and rare network protocols via modprobe. | Shrinks kernel attack surface; several are historic CVE sources. | D017 |
| C4.3 | Core dumps disabled. | Dumps leak keys and secrets to disk. | D017 |
| C4.4 | `umask 027`. | New files are not world-readable by default. | D017 |
| C4.5 | `cron`/`at` restricted to root. | Removes an unprivileged persistence path. | D017 |

Verify: compare `sysctl -a` against `audit/baseline/`.

---

## C5 — Accounts, password & lockout policy

| # | Control | Why | Ref |
|---|---|---|---|
| C5.1 | Password quality: minlen 14, 4 character classes. | CIS L1. Applies to the fallback credential, which is now the weakest link. | D017 |
| C5.2 | Account lockout via `faillock`. | Bounds offline-assisted online guessing. | D017 |
| C5.3 | Password aging enforced — **but** keep the global `login.defs` default long (365) so operator and root recovery passwords never silently expire. | An expired recovery password is a lockout with extra steps. | D034 |
| C5.4 | Short aging windows are scoped to onboarding accounts only. | Temp credentials should expire; permanent recovery credentials should not. | D034 |

---

## C6 — Audit & integrity

| # | Control | Why | Ref |
|---|---|---|---|
| C6.1 | auditd baseline rules: identity changes, sudoers, sshd config, sysctl, sessions, privilege escalation. | The minimum set that reconstructs "who changed what". | D017 |
| C6.2 | AIDE file-integrity database, initialised after hardening is complete. | Detects post-compromise tampering. Initialise *after* changes or the DB records the pre-hardened state. | D017 |
| C6.3 | Local durable trail: state snapshot at boot and daily (60-day retention), dated log exports (30-day). | No central log server is assumed; the local trail is the audit evidence. | D016 |
| C6.4 | Store the trail in the host's own corpus at `/root/<hostname>/`, mode `0700`, root-owned. | It contains replaced sudoers, original `sshd_config`, topology, and gateway MACs — treat as secret. | D000, D016 |

---

## C7 — DNS privacy

| # | Control | Why | Ref |
|---|---|---|---|
| C7.1 | Local `dnscrypt-proxy`; stub resolver forwards to it. | Terminates encrypted DNS locally so no cleartext query leaves the host. | D014 |
| C7.2 | Randomized pool of no-log, DNSSEC-validating, encrypted resolvers — `lb_strategy=random`, `require_nolog`, `require_dnssec`. | A single resolver, even an encrypted one, sees every lookup. Spreading defeats profiling. | D014 |
| C7.3 | Override ISP/DHCP-supplied DNS. | Otherwise DHCP silently reinstates the ISP resolver on every lease. | D014 |
| C7.4 | Disable LLMNR; keep mDNS if local discovery is wanted. | LLMNR is a name-poisoning and credential-relay vector with no modern use. | D005 |

Verify: `resolvectl status` shows the local stub only; a plain `dig` to an external resolver fails
(blocked by C8.1).

---

## C8 — Egress filtering & firewall

| # | Control | Why | Ref |
|---|---|---|---|
| C8.1 | Reject outbound plaintext HTTP (80/tcp) and plaintext DNS (53 udp+tcp); exempt loopback. | Makes cleartext egress structurally impossible rather than merely discouraged. | D015 |
| C8.2 | Inbound: exactly SSH + mDNS. Log denials. | Every other listener is a documented decision or a mistake. | D009 |
| C8.3 | Nothing binds a non-loopback interface without a written decision. | Default-deny on exposure, not default-allow. | D009 |
| C8.4 | Scoped exceptions get their own subnet-limited rule, never a global hole. | A legacy HTTP-only device justifies one route, not disabling C8.1. | D046 |

Verify: `ss -tulpn` shows only intentional non-loopback binds; `curl -v http://example.com` is
rejected while `https://` succeeds.

---

## C9 — Anti-MITM / layer 2

| # | Control | Why | Ref |
|---|---|---|---|
| C9.1 | Reverse-path filtering; reject ICMP redirects (accept and send); no source routing; martian logging. | Blocks the classic on-path redirection primitives. | D006 |
| C9.2 | ARP hardening (`arp_ignore` / `arp_announce`). | Reduces ARP-cache poisoning surface. | D006 |
| C9.3 | No IPv6 router advertisements accepted. | Rogue RA is the easiest MITM on a modern LAN. | D006 |
| C9.4 | Pin the gateway MAC per network (trust-on-first-connect, permanent ARP entry). | Neutralises gateway spoofing after the first clean association. | D012 |
| C9.5 | `arpwatch` for ARP-anomaly logging; `fail2ban` for SSH brute force. | Detection where prevention is not possible. | D011 |

---

## C10 — Outbound anonymity (optional layer) ⚠️🔁

| # | Control | Why | Ref |
|---|---|---|---|
| C10.1 | Tor with region-locked exits (`ExitNodes`, `StrictNodes 1`), standard 3-relay circuit. | Predictable exit jurisdiction without breaking circuit security. | D013 |
| C10.2 | Transparent torification: nftables redirects outbound TCP to Tor's `TransPort`. | Application-level proxy settings leak; the netfilter layer does not. | D013 |
| C10.3 | Exempt loopback, the `tor` user, LAN, established connections, and NTP. | Established-connection exemption preserves the live admin SSH session; Tor cannot carry UDP and needs an accurate clock. | D013 |
| C10.4 | Drop non-Tor UDP and ICMP to the internet. | Otherwise DNS and ping leak around the redirect. | D013 |
| C10.5 | Encrypted DNS rides Tor over TCP (`force_tcp`). | Tor carries no UDP. | D013 |
| C10.6 | **Apply behind a systemd dead-man auto-revert.** Keep only after a plain `curl` confirms a Tor exit IP *and* the SSH session is still up. | Applied remotely without this, a mistake is unrecoverable. | D021 |

Toggle via `scripts/toggle_tor.sh`; egress backend selection via `scripts/netmode.sh` (D039).

---

## C11 — Virtualization isolation

| # | Control | Why | Ref |
|---|---|---|---|
| C11.1 | Run untrusted or offensive tooling in a KVM/libvirt guest, not on the host. | Host stays clean; blast radius is the guest. | D040 |
| C11.2 | Rely on SELinux sVirt per-VM MCS labelling. | Guest-to-host and guest-to-guest isolation enforced by the kernel. | D040 |
| C11.3 | Graphics over a local unix socket (SPICE), never a TCP bind. | A TCP console is an unauthenticated remote desktop. | D040 |
| C11.4 | Choose guest egress explicitly: NAT (default), isolated (airgapped), or mirrored (LAN peer, wired uplink only). | Bridged-by-default silently puts an offensive guest on the LAN. | D040 |
| C11.5 | Containers run **rootless**, under an unprivileged account. | `docker` group membership is root-equivalent. | D047 |

---

## C12 — Maintenance & resilience

| # | Control | Why | Ref |
|---|---|---|---|
| C12.1 | Daily unattended refresh + upgrade, logged, then a guarded reboot. | Patch latency is the dominant real-world risk on a workstation. | D003, D016 |
| C12.2 | Every control persists via `sysctl.d` / `sshd_config.d` / systemd units / permanent firewall rules. | A control that does not survive reboot is not a control. | D016 |
| C12.3 | Verify the host returns hardened after reboot before considering any change complete. | Reboot survival is the acceptance test. | D016 |

---

## Accepted deviations from CIS

Documented, deliberate, and revisit-able. Each is a usability trade the owner accepted.

| Deviation | Rationale |
|---|---|
| `X11Forwarding yes` | Owner convenience. Adds an X11 attack path from a trusted client. |
| mDNS running and exposed (5353) | Local device discovery wanted. |
| SSH exposed on the LAN | Remote administration; mitigated by key-only + fail2ban. |
| No central log server | No infrastructure assumed; replaced by the 60-day local trail (C6.3). |
| `usb-storage` left enabled | Workstation use; CIS L1 would blacklist it. |
| Crypto policy DEFAULT not FUTURE | See C2.4 — FUTURE breaks ordinary HTTPS and updates. |

---

## Anti-patterns — recorded, **not** endorsed

The source host applied these under explicit owner override. They are in
[DECISIONS.md](DECISIONS.md) for honesty and rollback, and are listed here so an agent applying this
standard does not mistake them for prescriptions. **Do not apply these by default.**

| Anti-pattern | Why it is a regression | Ref |
|---|---|---|
| Blanket passwordless sudo (`NOPASSWD: ALL`) for an admin account | Discards C1.1 entirely — any process running as that user is root. | D038, D041 |
| Publishing a container on `0.0.0.0` | Violates C8.3; exposes a service to the whole LAN with no decision record. | D044 |
| Global browser TLS relaxation for one legacy device | Downgrades TLS for *all* browsing to reach one appliance. Scope it (stunnel bridge / per-site) or accept plain HTTP on a limited route. Rolled back on the source host. | D043, D043b, D044, D045 |
| Removing the passphrase from the commit-signing key | The signing key stops being a two-factor (have + know) secret; anyone with read access to the keyring can sign as the owner. | D048 |
| Chowning the config corpus off `root` | Any process running as the owner can then alter the audit evidence. Keep `/root/<hostname>/` root-owned `0700` (C6.4). | D049 |

---

## Verification summary

```bash
sshd -T | grep -E 'permitrootlogin|passwordauthentication|maxauthtries|ciphers'
visudo -c
getenforce                                  # Enforcing
ss -tulpn | grep -vE '127\.0\.0\.1|::1'     # only intentional exposures
systemctl is-enabled auditd fail2ban dnscrypt-proxy
resolvectl status | head -20
curl -sS http://example.com  || echo 'plaintext HTTP correctly rejected'
aide --check                                # after initialisation
```

Compare every result against `/root/<hostname>/audit/baseline/` and record the delta in that host's
`DECISIONS.md`.
