---
type: Overview
title: Secure Linux Desktop Standard — Fedora
description: Purpose, document map, and end-to-end setup procedure for applying this security- and anonymity-focused hardening baseline to a Fedora workstation.
tags: [fedora, hardening, cis-level-1, workstation, security-baseline, okf]
status: stable
stale_after: 2027-01-24
generated:
  by: claude-code/opus-5
  at: 2026-07-24T19:01:22-04:00
---

# Secure Linux Desktop Standard — Fedora

A reusable, security- and anonymity-focused hardening baseline for a single-owner Fedora
workstation. Target: **CIS Level 1** plus enterprise controls, with the reasoning for every choice
kept alongside the change.

This repository is the **standard**. It is host-neutral: no hostnames, addresses, key IDs, account
names, or personal identifiers. Everything host-specific lives on the host itself, never here.

This bundle conforms to the [Open Knowledge Format](https://github.com/GoogleCloudPlatform/knowledge-catalog/tree/main/okf)
(OKF) v0.2 — every document carries YAML frontmatter with a `type`, and [index.md](index.md) is the
navigable entry point for agents.

---

## Purpose

Two audiences, one corpus:

- **A human** wanting a documented, opinionated Fedora desktop baseline they can read, argue with,
  and apply.
- **An AI agent** pointed at this repository and told "configure this machine to the standard."
  The agent reads [CONTROLS.md](CONTROLS.md) for what to apply, [ARCHITECTURE.md](ARCHITECTURE.md)
  for how the pieces fit, and [DECISIONS.md](DECISIONS.md) for why — then records what it did in
  the host's own corpus (below).

---

## Documents

| File | Read it for |
|------|-------------|
| [index.md](index.md) | OKF bundle index. Start here if you are an agent. |
| [CONTROLS.md](CONTROLS.md) | **What to apply.** Ordered, prescriptive control list with verification. Start here if you are a human. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the controls compose — identity model, network exposure, DNS/Tor chain, recovery invariants. |
| [DECISIONS.md](DECISIONS.md) | Dated rationale log. Every control's *why*, the alternatives rejected, and its rollback. |
| `scripts/` | Executable pieces: hardening, network-mode switching, transparent-Tor toggle. |
| `vendor/` | Third-party source with verified provenance (`pam_ssh_agent_auth`) + SELinux policy. |

---

## Placeholders

Documents use angle-bracket placeholders. Substitute for the target host; never commit real values
back to this repo.

| Placeholder | Meaning |
|---|---|
| `<owner>` / `<owner-email>` | Primary admin account and its email |
| `<host>` / `<host-ip>` | Target hostname / its LAN address |
| `<lan-cidr>` / `<gateway-ip>` / `<gateway-mac>` | Local network, router address, pinned router MAC |
| `<wan-ip>` | The host's public address (used only in egress verification) |
| `<signing-key-id>` / `<fingerprint>` | Commit-signing key, SSH key fingerprints |
| `secbase-*` | Group / unit / sudoers naming prefix. Rename to taste, consistently. |

---

## Setup

### 0. Prerequisites

Fedora Workstation, UEFI + Secure Boot, LUKS full-disk encryption with a **retained passphrase
keyslot**, SELinux Enforcing. Console access you can physically reach. Do not start without these —
several controls can lock out remote access, and the console is the recovery path.

### 1. Create the host's config corpus

Every host keeps its own configuration record, separate from this standard:

```
/root/<hostname>/
├── ARCHITECTURE.md          # this host's deviations from the standard
├── DECISIONS.md             # append-only: what changed on THIS host, why, how to roll back
├── audit/
│   ├── baseline/            # pre-change state snapshot (step 2)
│   └── daily/               # dated state snapshots, 60-day retention
├── configs-backup/          # every original config file replaced, dated
└── exports/                 # dated log exports, 30-day retention
```

```bash
HOSTDIR=/root/$(hostnamectl --static)
sudo install -d -m 0700 "$HOSTDIR"/{audit/baseline,audit/daily,configs-backup,exports}
```

**`0700`, root-owned, and never committed anywhere.** It holds replaced sudoers files, original
`sshd_config`, wifi connection names, gateway MACs, LAN topology, and your audit trail. Treat it as
secret material. If you back it up, back it up encrypted.

Keeping this corpus in OKF form too — a `type: Host Record` document per change area, plus a
`log.md` — lets the same agent read the standard and the host's deviations with one parser.

### 2. Snapshot before you change anything

```bash
sudo bash -c 'D=/root/$(hostnamectl --static)/audit/baseline
  sshd -T                       > "$D/sshd-T.txt"
  update-crypto-policies --show > "$D/crypto-policy.txt"
  ss -tulpn                     > "$D/listening-ports.txt"
  resolvectl status             > "$D/resolvectl.txt"
  sysctl -a                     > "$D/sysctl-all.txt"
  firewall-cmd --list-all-zones > "$D/firewall.txt"
  systemctl list-unit-files --state=enabled > "$D/enabled-units.txt"
  getenforce                    > "$D/selinux.txt"
  lsmod                         > "$D/lsmod.txt"
  rpm -qa | sort                > "$D/installed-packages.txt"
  cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.d "$D/"
  date -Is                      > "$D/_timestamp.txt"'
```

This is the rollback reference for everything that follows. Without it, several changes are not
safely reversible.

### 3. Apply the controls

Work through [CONTROLS.md](CONTROLS.md) top to bottom. It is ordered so nothing locks you out
before its recovery path exists. For each control:

1. Back up the file you are about to change into `configs-backup/` (dated).
2. Apply.
3. **Validate before restart** — `sshd -t`, `visudo -c`, `nft -c -f`, as applicable.
4. Append an entry to `/root/<hostname>/DECISIONS.md`: what, why, how, rollback.

`scripts/harden.sh` implements the bulk of the CIS L1 layer and is idempotent — read it before
running it. `scripts/netmode.sh` and `scripts/toggle_tor.sh` change live networking; see
`CONTROLS.md` §C10.

### 4. Keep a console open during SSH, PAM, and firewall changes

Any change to `sshd_config`, `/etc/pam.d/*`, or the firewall can end your session permanently.
Keep a second, already-authenticated session open, and prefer the dead-man pattern used by
`toggle_tor.sh` (auto-revert on a timer unless explicitly confirmed) for anything applied remotely.

### 5. Verify

Run the verification block at the end of [CONTROLS.md](CONTROLS.md), compare against
`audit/baseline/`, and record the delta.

---

## For an AI agent configuring a host

1. Read [index.md](index.md), then [CONTROLS.md](CONTROLS.md), [ARCHITECTURE.md](ARCHITECTURE.md),
   [DECISIONS.md](DECISIONS.md) in that order.
2. Create and populate `/root/<hostname>/` (steps 1–2). **Do not proceed without the baseline
   snapshot.**
3. Apply controls in the order given, one at a time, validating each before moving on.
4. Log every change to `/root/<hostname>/DECISIONS.md` — what, why, how, rollback. No silent
   changes.
5. Read the **Anti-patterns** section of `CONTROLS.md` and do not apply those, even though they
   appear in the decision log.
6. **Stop and ask the owner** before: removing a LUKS keyslot, disabling console login, changing
   SELinux mode, removing the last working SSH key, or anything else that could remove the recovery
   path. Elsewhere: choose the more secure option by default.
7. Never copy anything from `/root/<hostname>/` into this repository or any other remote. Host
   specifics stay on the host.

---

## Scope

Covered: identity and privilege model, SSH, sudo, kernel sysctl, module blacklisting, password and
lockout policy, auditd, AIDE, DNS privacy, egress filtering, anti-MITM/ARP, transparent Tor,
libvirt guest isolation, rootless containers, unattended update/reboot, local audit retention.

Not covered: centralised logging, MDM/fleet management, backup strategy, physical security.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
