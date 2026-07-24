---
type: Rationale
title: Rationale — why each control is what it is
description: Per-control reasoning for the standard — the threat addressed, the alternatives rejected and why, operational caveats, and the rollback. Keyed to the control IDs in CONTROLS.md.
tags: [rationale, design, threat-model, rejected-alternatives, rollback]
status: stable
stale_after: 2027-01-24
generated:
  by: claude-code/opus-5
  at: 2026-07-24T19:01:22-04:00
sources:
  - resource: /CONTROLS.md
    title: The controls this document explains
---

# Rationale

Every control in [CONTROLS.md](CONTROLS.md) appears here under the same ID, with the reasoning that
produced it: what it defends against, what was tried or rejected, the caveats that bite in practice,
and how to undo it.

This document describes the **standard**. Any host will deviate from it somewhere; those deviations
belong in that host's own record at `/root/<hostname>_security_config/`, never here.

---

## C1 — Identity & privilege model

### C1.1 — No blanket `NOPASSWD: ALL`
**Why.** For unattended automation the command whitelist *is* the security boundary — there is no
human to authenticate at the moment of use. A blanket grant makes any code execution as that
account equivalent to root, which collapses every other control in this document.
**Rejected.** `%wheel ALL=(ALL) NOPASSWD: ALL`. It is the path of least resistance and it is what
everyone reaches for when key-auth sudo proves awkward (C3). Resist it. "Key-auth sudo doesn't work
from my client" is almost always a client-configuration problem with a known fix (C3 client
requirements) — fix the client. Unattended service accounts that genuinely cannot present a key get
a *scoped* command group (C3.6), never an unscoped grant.
**Rollback.** Remove the role file from `/etc/sudoers.d/`; `visudo -c`.

### C1.2 — Agents get a dedicated `nologin` service account
**Why.** Two independent boundaries: the account cannot be logged into, and the sudo grant is a
narrow command list. Either alone is weak; together they bound what a compromised automation
credential can reach.
**Rejected.** Running agents as a human's account. Convenient, and it silently grants the agent everything
the human has.
**Rollback.** `userdel -r <agent>`; remove its role file.

### C1.3 — One ed25519 key per agent, used for both SSH and escalation
**Why.** A single credential per identity means revocation is one key removal, and the same
provisioning path works for remote humans and headless service accounts alike. Agents frequently
arrive with no key at all — generating one is part of the standard provisioning process, not an
exception.
**Rejected.** Shared keys across agents (revocation becomes all-or-nothing); separate login and
sudo credentials (doubles the enrolment and revocation surface for no gain).
**Rollback.** `rm /etc/security/sudo_authorized_keys.d/<name>.pub` and the account's
`authorized_keys` entry.

### C1.4 — `use_pty` and a dedicated sudo log
**Why.** `use_pty` defeats TTY-hijacking of an authenticated sudo session. The dedicated log gives
an escalation trail independent of the journal.
**Rollback.** Remove `Defaults use_pty` and `Defaults logfile=` from the alias file.

### C1.5 — A second standing admin account
**Why.** Every control here has a lockout mode. A second admin built by the same mechanism — key-only
login, same sudo path — is the difference between "reconfigure over SSH" and "carry the machine to a
console".
**Caveat.** Build it with its own keypair. A second admin sharing the first one's key is not a
second recovery path.
**Rollback.** `userdel -r <second-admin>`; remove its key-store entry.

### C1.6 — Scoped, self-closing onboarding for a user's *first* key
**Why.** A key-only host (C2.1) has a bootstrap problem: `ssh-copy-id` needs password auth to
install the first key, and it never touches the sudo key-store anyway. Without a bridge, every new
user needs an admin to hand-install their key.
**How the bridge stays safe.** Password auth is re-enabled *only* by
`Match Group onboarding Address <lan-cidr>` — global `PasswordAuthentication no` still applies to
everyone else, which `sshd -T -C` will confirm per-user. The window is contained by five things at
once: LAN-only scope, fail2ban, faillock, a 10-day password expiry, and self-closure — a path unit
watching `authorized_keys` promotes the user on first key write (key → sudo key-store, `+wheel`,
`-onboarding`, aging normalised), revoking the password path in about two seconds.
**Critical scoping.** The 10-day expiry applies to onboarding accounts **only**. A global
`PASS_MAX_DAYS=10` expires the administrator and root passwords and destroys the console recovery path
(C5.3). Keep the `login.defs` default long.
**Rejected.** Admin-installed first keys (does not scale, and the admin ends up handling other
people's private keys); a permanent password exception (never self-closes).
**Rollback.** Remove the sshd drop-in and reload; remove the templated path/service units and the
onboard/promote scripts; `groupdel onboarding`.

---

## C2 — SSH

### C2.1–C2.2 — Key-only, no root login, bounded auth attempts
**Why.** Removes the brute-forceable credential entirely and bounds what remains. The physical
console stays as the lockout fallback — which is why C2 is not safe to apply to a host you cannot
physically reach.
**Before reloading, always.** Confirm your live session authenticated by **publickey** (not
password) and that your key is actually in `authorized_keys`. `sshd -t`, then reload with a second
session open.
**Rollback.** Restore the baseline `sshd_config` + `sshd_config.d` captured before any change.

### C2.3–C2.4 — Pin SSH algorithms; keep system crypto policy at DEFAULT
**Why this specific split.** The obvious move is `update-crypto-policies --set FUTURE`. Do not.
FUTURE rejects RSA-2048 certificate chains, which is most of the public web including Let's Encrypt
— a plain `curl https://…` returns `000` under FUTURE and `200` under DEFAULT, and the `dnf`
auto-updater (C12.1) breaks with it. The result is a host that cannot patch itself, which is a net
security loss.
**What to do instead.** Leave the system policy at DEFAULT — still TLS 1.2+, no SHA-1 signatures,
no weak ciphers — and pin modern algorithms *explicitly in sshd*: chacha20-poly1305 and AES-GCM
ciphers, SHA-2 ETM MACs, sntrup761x25519 and curve25519 KEX. SSH is then hardened independently of
whatever the system policy is set to.
**Rollback.** Remove the pinned algorithm lines; `update-crypto-policies --set DEFAULT`.

### C2.6 — Agent forwarding, scoped
**Why.** Remote key-auth sudo (C3) cannot work without it — the module can only verify a key that
the caller's agent presents, and a remote caller's agent is reachable only by forwarding. This is
load-bearing, not optional.
**The risk, stated plainly.** A compromised host can use a connected user's forwarded agent for the
lifetime of the session. The standard accepts that in exchange for eliminating typed passwords from
the escalation path entirely.
**How to keep the exchange honest.** Scope it with `Match Group` to the accounts that actually
escalate, rather than enabling it globally. Keep `AllowTcpForwarding no` regardless. If a host has
no accounts using C3, forwarding should be off there — carrying the risk without the benefit is the
one configuration to avoid.
**Rollback.** `AllowAgentForwarding no`; `sshd -t`; reload.

### Operational note — multi-key agents cause self-lockouts
An SSH agent holding several keys offers them one at a time. Against `MaxAuthTries 4` plus a
fail2ban `maxretry` of 4, connecting to an account that has not enrolled that agent's *first* key
burns the attempt budget and bans the source IP — locking you out of **every** account from that
host, including working ones.

This is the single most common reason key-auth sudo (C3) gets abandoned as "broken from my client".
It is not the module failing; it is the client offering the wrong key first. The fix is client-side
and is part of the standard (`CONTROLS.md` C3 client requirements): `IdentitiesOnly yes` with an
explicit `IdentityFile`, and named `Host` aliases rather than a bare-IP block.

Exempting a source IP from throttling treats the symptom and removes the protection for that
address. Fix the client instead; if an exemption is genuinely unavoidable, it is a host deviation,
not a control.

---

## C3 — Sudo authentication by SSH key

### C3.1–C3.3 — `pam_ssh_agent_auth` first, password stack retained
**Why.** Separates authentication (key possession) from authorization (the `Cmnd_Alias` role
groups). The operator proves identity with the same credential they already use for SSH, and no
password is typed anywhere in the automation path.
**This is the standard's escalation mechanism, not an experiment.** The key is the universal
credential: the same ed25519 identity authenticates SSH login and sudo, for humans and for agents.
Nothing in the automation path types a password. Where an organization cannot make this work, the
gap is almost always client configuration (see C2.6 and the client requirements in `CONTROLS.md`),
not the mechanism.
**Why the fallback stays.** The password stack below the module is what prevents this from being a
lockout. Never remove it. `%u` in the key-store path resolves to the *invoking* user at auth time,
so per-caller files behave correctly.
**Caveat that wastes an afternoon.** `sudo -n` short-circuits before PAM and never invokes the
module — it will always look like the module is broken. Test with a real tty, or
`sudo <cmd> </dev/null`.
**Console path.** Interactive sudo at the physical console deliberately uses the faillock-protected
password, so no private key needs to live at rest on the machine. A passphrased or FIDO2 (`-sk`)
console key is a reasonable option if you want keyless console sudo; it is a deliberate addition,
not the default.
**Rollback.** Remove the `pam_ssh_agent_auth` line from `/etc/pam.d/sudo` (or restore the captured
baseline). Sudo reverts to the password stack.

### C3.4 — Build the module from verified upstream source
**Why.** `pam_ssh_agent_auth` is not packaged by Fedora, EPEL, or RHEL — checked across koji,
dist-git, EPEL 8/9/10 and the EL7/EL8 vaults. Something that authenticates root escalation cannot be
installed from an unverified binary.
**Chain to establish.** Debian's maintained source package, fetched by hash, `.dsc` checksums
matched against both tarballs independently, and the `.dsc` PGP signature verified against a
signer confirmed in Debian's developer database. See `vendor/pam_ssh_agent_auth/PROVENANCE.md`.
**Rejected.** `pam_u2f` — per-agent hardware tokens are a poor fit for headless service accounts.
**Operational.** The module is not RPM-owned, so `dnf` will not remove it — but an OpenSSL or PAM
ABI bump on update can require a rebuild. Re-run `build-and-install.sh`. The installer must be
non-fatal: a build failure has to leave sudo working.

---

## C4 — Kernel & module hardening

### C4.1–C4.5
**Why.** These remove the standard local-privilege-escalation primitives: kernel pointer and dmesg
exposure, `ptrace` on unrelated processes, SUID core dumps, symlink/hardlink races in shared
directories, unprivileged BPF, and perf events.
**Deliberately left enabled.** User namespaces — browser and flatpak sandboxes depend on them, and
disabling them trades a real, daily-used sandbox for a theoretical one.
**Module blacklisting.** Rare filesystems (cramfs, freevxfs, hfs, hfsplus, jffs2, squashfs, udf) and
rare network protocols (dccp, sctp, rds, tipc). These are recurring CVE sources with no desktop use.
**Commonly deferred.** Separate `/tmp` and `/var/tmp` with `nodev,nosuid,noexec` — correct, but it
needs a maintenance window or a subvolume change on a live host. Do it when building an image, not
when hardening a running one.
**Rollback.** Remove the named `sysctl.d` and `modprobe.d` drop-ins; `sysctl --system`.

---

## C5 — Accounts, password & lockout policy

### C5.1–C5.2
**Why.** Once C2.1 removes password auth from SSH, the password becomes the *console and sudo
fallback* credential — the last recovery path. Quality and lockout policy protect exactly that.
**Rollback.** `authselect disable-feature with-faillock`; remove the pwquality drop-in.

### C5.3–C5.4 — Keep the global aging default long
**Why this is a security control and not a convenience.** Short global password aging expires the
owner and root credentials on a schedule. Those are the console recovery path. An expired recovery
password is a lockout that arrives on a timer, and it will arrive at the worst moment. Scope short
expiry to temporary accounts (C1.6); leave the `login.defs` default at 365.

---

## C6 — Audit & integrity

### C6.1–C6.2
**Why.** The auditd rule set is chosen to reconstruct "who changed what": identity changes, sudoers,
sshd config, sysctl, sessions, privilege escalation.
**Ordering that matters.** Initialise AIDE **after** hardening is complete. Initialise it first and
the database records the pre-hardened state, so every subsequent check reports your own hardening as
tampering, and the tool gets ignored.
**Note.** Audit rules are left mutable on a host that reboots daily; immutable (`-e 2`) is correct
for a host that does not.

### C6.3–C6.4 — Local durable trail, root-owned
**Why.** With no central log server, the local trail *is* the audit evidence — a boot-time and daily
state snapshot with 60-day retention, plus dated log exports at 30 days. A snapshot at every boot
means the trail has no gaps regardless of the reboot schedule.
**Why root-owned `0700`.** The corpus holds replaced sudoers files, the original `sshd_config`,
gateway MACs, wifi connection names, and LAN topology. It is secret material, and if a non-root
account can write to it, the audit evidence is no longer evidence. Granting a role group write access
to `/var/log` has the same effect: it lets members modify or delete any log, including the escalation
trail. Prefer read access, or a dedicated directory.
**Rollback.** Remove the maintenance cron entries and disable the boot-audit unit.

---

## C7 — DNS privacy

### C7.1–C7.3 — Randomized pool, not a single provider
**Why the pool.** A single encrypted resolver — even a reputable no-log one — still sees every
lookup the host makes. That is a complete browsing profile held by one operator. Spreading queries
across many no-log, DNSSEC-validating resolvers with `lb_strategy=random` means no single operator
can build one.
**Rejected.** A fixed pair of well-known resolvers over DoT. Encrypted and validated, and still a
single point of observation. It is the right *first* step and the wrong *final* one.
**Configuration that bites.** Set `netprobe_timeout=0` — the default connectivity probe uses
plaintext port 53, which C8.1 blocks, and the daemon will fail to start. Override DHCP-pushed DNS
explicitly (`ignore-auto-dns`), or the ISP resolver returns on the next lease.
**Available enhancement.** Anonymized DNS or ODoH relays, where the resolver never sees the client
IP.
**Rollback.** Restore the previous resolved drop-in; `systemctl disable --now dnscrypt-proxy`.

### C7.4 — Disable LLMNR, keep mDNS if wanted
**Why.** LLMNR is a name-resolution poisoning and credential-relay vector with no modern use, and it
is redundant with mDNS. mDNS is a genuine local-discovery feature; keeping it is a defensible choice
that costs an exposed UDP port.

---

## C8 — Egress filtering & firewall

### C8.1 — Reject outbound plaintext HTTP and DNS
**Why.** This is the control that makes "we use HTTPS everywhere" structurally true instead of
aspirational. It blocks cleartext exfiltration paths and plaintext-DNS leaks that would otherwise
bypass C7 entirely. Loopback is exempt.
**Expect to fix things.** Package build scripts and appliance firmware reach for port 80 by habit.
The right fix is to move the client to HTTPS, not to remove the rule.
**Rollback.** Remove the direct rules; reload.

### C8.2–C8.4 — Default-deny exposure
**Why.** Inbound is exactly SSH and mDNS, with denials logged. Everything else that listens on a
non-loopback interface is either a written decision or a mistake — and the point of the rule is that
you can tell which by reading the record.
**Where this erodes in practice.** Container runtimes publish ports on `0.0.0.0` by default. A
`-p 8080:8080` is a LAN exposure with no decision attached to it. Bind published ports to `127.0.0.1`
explicitly unless LAN exposure is the intent, and audit `ss -tulpn` against the record regularly —
drift here is silent.
**Scoped exceptions.** A legacy HTTP-only device justifies one subnet-limited rule, not disabling
C8.1 globally. The same logic applies to TLS: relaxing browser TLS settings to reach one appliance
downgrades *all* browsing. Bridge it (e.g. a loopback-bound stunnel) or accept plain HTTP on one
narrow route.

---

## C9 — Anti-MITM / layer 2

### C9.1–C9.3
**Why.** Closes the classic on-path primitives: ICMP redirects, source routing, ARP-spoof assist,
and rogue router advertisements. Reverse-path filtering and martian logging cover the rest.
**Note.** `accept_ra=0` disables IPv6 SLAAC autoconfiguration. That is the point — rogue RA is the
easiest MITM on a modern LAN — but confirm IPv4 is your primary path first.

### C9.4–C9.5 — Pin the gateway, then watch it
**Why.** Trust-on-first-connect: on connect or DHCP change, pin the default gateway's IP→MAC as a
permanent neighbour entry, per interface. Once pinned, a spoofed ARP reply cannot redirect gateway
traffic. Log every pin and alert on any change.
**Why both.** Pinning prevents; arpwatch and fail2ban detect what pinning cannot. Neither
substitutes for the other.
**Rollback.** Remove the dispatcher script; `ip neigh flush nud permanent`.

---

## C10 — Outbound anonymity

### C10.1 — Region-locked exits, default hop count
**Why.** `ExitNodes` with `StrictNodes 1` gives a predictable exit jurisdiction. Leave the circuit
at Tor's default 3 relays — reducing it is unsupported and breaks the anonymity property that makes
Tor worth using.

### C10.2–C10.5 — Redirect at netfilter, and mind what Tor cannot carry
**Why netfilter.** Application-level proxy settings leak; anything that ignores them egresses in the
clear. An nftables redirect of outbound TCP into Tor's `TransPort` does not have that failure mode.
**The exemptions are load-bearing** and must be ordered first: loopback, the `tor` user's own
traffic, RFC1918 and link-local destinations, established/related connections — this is what
preserves a live admin SSH session — and NTP. Tor cannot carry UDP and needs an accurate clock, so
NTP goes direct. Drop all other non-Tor UDP and ICMP to the internet, or DNS and ping leak around
the redirect.
**DNS.** Rides Tor over TCP (`force_tcp`) rather than a Tor DNSPort. This also sidesteps a SELinux
UDP `name_bind` issue on the Tor port type — keep SELinux Enforcing and label the port properly with
`semanage` rather than reaching for a permissive shim.
**Boot behaviour.** For roughly 30–60 seconds after each reboot, web and DNS wait for Tor to
bootstrap. SSH and LAN are unaffected. Expect it, or you will debug it.

### C10.6 — The dead-man is not optional
**Why.** A torification kill-switch on a remotely administered host can sever SSH and break the
auto-updater. Apply behind a systemd-timer auto-revert, and cancel the timer only after a plain
`curl` confirms a Tor exit address *and* the SSH session is still alive.
**Toggling off must disable, not just stop.** If the unit is merely stopped, the daily reboot
silently re-enables it.
**Rollback.** `systemctl disable --now <killswitch>`; remove the torrc drop-in.

---

## C11 — Virtualization & container isolation

### C11.1–C11.4
**Why.** Tooling you would not run on the host runs in a guest, with SELinux sVirt per-VM MCS
labelling as the enforced boundary. Console graphics over a local unix socket — a TCP-bound console
is an unauthenticated remote desktop.
**Egress is an explicit choice.** NAT (outbound only), isolated (no forwarding), or mirrored (LAN
peer). Bridged-by-default silently places a guest on the LAN as a peer; decide rather than inherit.

### C11.5 — Rootless containers
**Why.** Membership of the `docker` group is root-equivalent. Rootless removes that escalation path
by running the daemon as an unprivileged user.
**Costs to plan for.** Binding ports below 1024 needs
`net.ipv4.ip_unprivileged_port_start` lowered — which permits *any* unprivileged process to bind
that range host-wide, so it is a real trade. Do not try `setcap cap_net_bind_service` on
`slirp4netns` or `rootlesskit`; it breaks their network-namespace operations. Source-IP fidelity
needs the slirp4netns port driver, since the builtin driver SNATs every client to one internal
address. Container DNS must point at slirp's resolver.

---

## C12 — Maintenance & resilience

### C12.1–C12.3
**Why.** Patch latency is the dominant real-world risk on a workstation, so updates are unattended
and off-hours, staged before a guarded reboot applies them.
**Reboot survival is the acceptance test.** Every control persists as `sysctl.d` / `sshd_config.d` /
systemd units / permanent firewall rules. A control that does not come back after reboot is not a
control, and the daily reboot is what proves it — treat the first reboot after any change as part of
applying that change.
**Rollback.** Remove the maintenance cron file; disable the boot-audit unit.
