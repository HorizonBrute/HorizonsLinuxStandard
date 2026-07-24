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
  - resource: /RATIONALE.md
    title: Why each control is what it is
  - resource: /ARCHITECTURE.md
    title: How the controls compose
---

# Controls

Apply in the order given. The order is deliberate: each control's recovery path exists before the
control that could remove it.

Reasoning for every control — threat addressed, alternatives rejected, caveats, rollback — is in
[RATIONALE.md](RATIONALE.md) under the **same ID**.

**Before anything:** capture the baseline snapshot (`README.md` §2). Several controls are not safely
reversible without it.

**This document is the standard, not a description of any host.** It contains no deviations. Where a
host must differ, that difference is recorded in the host's own register — see
[Deviating from this standard](#deviating-from-this-standard).

**Legend:** ⚠️ = can lock you out; keep a console session open.

---

## C1 — Identity & privilege model

| # | Control |
|---|---|
| C1.1 | No blanket `NOPASSWD: ALL`. Privilege is scoped by `Cmnd_Alias` command group + group grant. |
| C1.2 | Automated agents run as a dedicated non-login (`nologin`) service account, never as a human's. |
| C1.3 | Each agent is a key-bearing identity: one ed25519 key, used for both SSH and escalation. |
| C1.4 | Sudo: `use_pty` and a dedicated sudo log enabled. |
| C1.5 | A second standing admin account, key-only, with its **own** keypair. |
| C1.6 | First-key onboarding, if offered, is scoped (`Match Group … Address <lan-cidr>`), time-boxed, and self-closing on first key upload. |

Verify: `sudo -l -U <account>` shows only the intended aliases; `getent passwd <agent>` shows
`nologin`; `visudo -c` clean.

---

## C2 — SSH ⚠️

| # | Control |
|---|---|
| C2.1 | Key-only auth: `PasswordAuthentication no`, `PermitRootLogin no`. |
| C2.2 | `MaxAuthTries 4`, `LoginGraceTime 60`, idle timeout set. |
| C2.3 | Pin modern algorithms explicitly — chacha20-poly1305 / AES-GCM ciphers, SHA-2 ETM MACs, curve25519 + sntrup761 KEX. |
| C2.4 | System crypto policy stays **DEFAULT**, not FUTURE. FUTURE breaks RSA-2048 chains, most HTTPS, and `dnf`. |
| C2.5 | Verbose SSH logging; no banner; GSSAPI off. |
| C2.6 | `AllowTcpForwarding no`. Agent forwarding **on**, scoped with `Match Group` to those who escalate — remote key-auth sudo (C3) requires it. |
| C2.7 | `X11Forwarding no`. |

**Validate `sshd -t` before every restart, with a second authenticated session open.** Confirm your
live session authenticated by *publickey* first. This is the single most common lockout.

Verify: `sshd -T | grep -E 'permitrootlogin|passwordauthentication|maxauthtries|x11forwarding'`.

---

## C3 — Sudo authentication by SSH key

| # | Control |
|---|---|
| C3.1 | `pam_ssh_agent_auth` as first `auth` rule in `/etc/pam.d/sudo`, `sufficient`, **password stack retained below**. |
| C3.2 | Per-caller key store at `/etc/security/sudo_authorized_keys.d/%u.pub`, root-owned. |
| C3.3 | `SSH_AUTH_SOCK` preserved via `env_keep`. |
| C3.4 | Build the module from GPG-verified upstream source and vendor it; the installer must degrade safely if the build fails. |
| C3.5 | **Key-auth sudo is the escalation path for every interactive account.** No typed password in the automation path. |
| C3.6 | Scoped `NOPASSWD` command groups are for **unattended service accounts only** — accounts with no agent to present a key. They are an authorization mechanism, never a substitute for C3.5. |

**Client requirements (C3 fails without these).** The module verifies a key held by the caller's
agent, so the client must present the *right* key:

- `IdentitiesOnly yes` with an explicit `IdentityFile` per host — an agent holding several keys
  offers them serially and will burn `MaxAuthTries` (C2.2) before reaching the right one.
- Named `Host` aliases in `~/.ssh/config`, never a bare-IP block — a bare-IP entry forces one
  identity onto every connection to that address, including other accounts on the same host.
- `ForwardAgent yes` for the hosts you escalate on, and an agent actually holding the key.

Verify end-to-end from a real tty — **not** `sudo -n`, which short-circuits before PAM and always
looks like failure. Never remove the password fallback beneath the module.

---

## C4 — Kernel & module hardening (CIS L1)

| # | Control |
|---|---|
| C4.1 | sysctl: ASLR on, `kptr_restrict`, `dmesg_restrict`, `ptrace_scope`, `suid_dumpable=0`, protected hardlinks/symlinks/fifos/regular, restricted BPF, `perf_event_paranoid`. User namespaces left enabled (browser/flatpak sandboxes). |
| C4.2 | Blacklist unused filesystems (cramfs, freevxfs, hfs, hfsplus, jffs2, squashfs, udf), rare network protocols (dccp, sctp, rds, tipc), and `usb-storage`. |
| C4.3 | Core dumps disabled. |
| C4.4 | `umask 027`. |
| C4.5 | `cron`/`at` restricted to root. |
| C4.6 | Separate `/tmp` and `/var/tmp` with `nodev,nosuid,noexec`. Do this at image build time. |

Verify: compare `sysctl -a` and `lsmod` against `audit/baseline/`.

---

## C5 — Accounts, password & lockout policy

| # | Control |
|---|---|
| C5.1 | Password quality: minlen 14, 4 character classes, `enforce_for_root`. |
| C5.2 | Account lockout via `faillock` (deny 5, unlock 15m, root not locked). |
| C5.3 | Keep the global `login.defs` aging default long (365) so console and root recovery credentials never silently expire. |
| C5.4 | Short aging windows are scoped to temporary/onboarding accounts only. |

---

## C6 — Audit & integrity

| # | Control |
|---|---|
| C6.1 | auditd baseline rules: identity changes, sudoers, sshd config, sysctl, sessions, privilege escalation. |
| C6.2 | AIDE file-integrity database, initialised **after** hardening is complete. |
| C6.3 | Local durable trail: state snapshot at boot and daily (60-day retention), dated log exports (30-day). |
| C6.4 | Trail lives in the host corpus at `/root/<hostname>_security_config/`, mode `0700`, **root-owned**. `/var/log` stays root-owned and non-group-writable. |

---

## C7 — DNS privacy

| # | Control |
|---|---|
| C7.1 | Local `dnscrypt-proxy`; the stub resolver forwards to it. |
| C7.2 | Randomized pool of no-log, DNSSEC-validating, encrypted resolvers — `lb_strategy=random`, `require_nolog`, `require_dnssec`. |
| C7.3 | Override ISP/DHCP-supplied DNS (`ignore-auto-dns`). Set `netprobe_timeout=0` — the default probe uses plaintext 53, which C8.1 blocks. |
| C7.4 | Disable LLMNR. Keep mDNS only if local discovery is wanted. |

Verify: `resolvectl status` shows the local stub only.

---

## C8 — Egress filtering & firewall

| # | Control |
|---|---|
| C8.1 | Reject outbound plaintext HTTP (80/tcp) and plaintext DNS (53 udp+tcp); exempt loopback. |
| C8.2 | Inbound: exactly SSH + mDNS. Default target deny. Log denials. |
| C8.3 | Nothing binds a non-loopback interface without a written decision. **Bind published container ports to `127.0.0.1` explicitly** — runtimes default to `0.0.0.0`. |
| C8.4 | Scoped exceptions get their own subnet-limited rule, never a global hole. Never relax browser or system TLS globally to reach one appliance. |

Verify: `ss -tulpn | grep -vE '127\.0\.0\.1|::1'` returns only SSH and mDNS. Audit this regularly —
drift here is silent.

---

## C9 — Anti-MITM / layer 2

| # | Control |
|---|---|
| C9.1 | `rp_filter=1`, no ICMP redirects (accept or send), no source routing, `log_martians=1`, `tcp_syncookies=1`. |
| C9.2 | ARP hardening: `arp_ignore=1`, `arp_announce=2`. |
| C9.3 | `accept_ra=0` — no IPv6 router advertisements. Confirm IPv4 is the primary path first. |
| C9.4 | Pin the gateway MAC per network (trust-on-first-connect, permanent ARP entry); log pins, alert on change. |
| C9.5 | `arpwatch` for ARP-anomaly logging; `fail2ban` for SSH brute force. |

---

## C10 — Outbound anonymity (optional layer) ⚠️

| # | Control |
|---|---|
| C10.1 | Tor with region-locked exits (`ExitNodes`, `StrictNodes 1`), default 3-relay circuit. |
| C10.2 | Transparent torification: nftables redirects outbound TCP to Tor's `TransPort`. |
| C10.3 | Exemptions ordered first: loopback, the `tor` user, RFC1918 + link-local, established/related (preserves the live SSH session), and NTP. |
| C10.4 | Drop non-Tor UDP and ICMP to the internet. |
| C10.5 | Encrypted DNS rides Tor over TCP (`force_tcp`). Keep SELinux Enforcing; label the Tor port with `semanage` rather than using a permissive shim. |
| C10.6 | **Apply behind a systemd dead-man auto-revert.** Keep only after a plain `curl` confirms a Tor exit IP *and* the SSH session is still up. Toggling off must `disable` the unit, not just stop it. |

Toggle via `scripts/toggle_tor.sh`; egress backend selection via `scripts/netmode.sh`.

---

## C11 — Virtualization & container isolation

| # | Control |
|---|---|
| C11.1 | Run untrusted or offensive tooling in a KVM/libvirt guest, not on the host. |
| C11.2 | Rely on SELinux sVirt per-VM MCS labelling. |
| C11.3 | Guest graphics over a local unix socket (SPICE), never a TCP bind. |
| C11.4 | Choose guest egress explicitly: NAT (default), isolated, or mirrored. |
| C11.5 | Containers run **rootless**, under an unprivileged account. `docker` group membership is root-equivalent. |

---

## C12 — Maintenance & resilience

| # | Control |
|---|---|
| C12.1 | Daily unattended refresh + upgrade, logged, then a guarded reboot. |
| C12.2 | Every control persists via `sysctl.d` / `sshd_config.d` / systemd units / permanent firewall rules. |
| C12.3 | Verify the host returns hardened after reboot before considering any change complete. |

---

## Deviating from this standard

Every real host deviates somewhere. A deviation is legitimate when it is **recorded**, and a
liability when it is not — an undocumented open port is indistinguishable from a compromise.

Deviations do **not** belong in this repository. They belong in the host's own record:

```
/root/<hostname>_security_config/DEVIATIONS.md
```

Record each one against the control ID it departs from:

```markdown
### <control-id> — <one-line summary>
**Deviation.** What differs from the standard.
**Why.** What the host is for, and why the control cannot apply as written.
**Risk accepted.** What protection is lost, stated plainly.
**Compensating control.** What limits the exposure instead, if anything.
**Review.** Date to revisit, or the condition that ends the deviation.
🔁 **Rollback.** Exact commands to return to the standard.
```

Two rules make the register worth keeping:

1. **Reconcile against live state, not against intent.** Run the C8.3 verification and diff the
   result against the register. Ports appear without anyone deciding to expose them — a container
   restart with a changed flag is enough.
2. **A deviation with no review date is a permanent decision.** Write the date, or admit it is
   permanent.

---

## Verification summary

```bash
sshd -T | grep -E 'permitrootlogin|passwordauthentication|maxauthtries|x11forwarding|ciphers'
visudo -c
sudo grep -rn 'NOPASSWD: *ALL' /etc/sudoers /etc/sudoers.d/   # expect no uncommented hits
getenforce                                  # Enforcing
ss -tulpn | grep -vE '127\.0\.0\.1|::1'     # only SSH + mDNS
stat -c '%A %U:%G' /var/log                 # root-owned, not group-writable
systemctl is-enabled auditd fail2ban dnscrypt-proxy
resolvectl status | head -20
curl -sS http://example.com || echo 'plaintext HTTP correctly rejected'
aide --check                                # after initialisation
```

Compare every result against `/root/<hostname>_security_config/audit/baseline/`. Record each difference in that
host's `DEVIATIONS.md` or fix it.
