# Directory Update Log

## 2026-07-24
* **Creation**: Bundle published as a host-neutral standard. Corpus extracted from a live hardened Fedora workstation and genericized — all hostnames, addresses, gateway MAC, WAN address, account names, key IDs, and personal identifiers replaced with angle-bracket placeholders. Host-specific material (audit trail, replaced configs, log exports, key material) deliberately excluded and retained only on the host.
* **Creation**: `CONTROLS.md` — prescriptive control set distilled from the decision log, ordered so each control's recovery path exists before the control that could remove it. Includes an **Anti-patterns** section recording owner-override regressions that the standard does not endorse.
* **Creation**: `README.md` — purpose, placeholder glossary, setup procedure, and the `/root/<hostname>/` host-corpus convention for keeping per-host configuration and change log separate from the standard.
* **Creation**: `index.md`, `log.md` — OKF bundle index and history.
* **Update**: `SECURITY-DECISIONS.md` renamed to `DECISIONS.md`; all documents given OKF v0.2 YAML frontmatter with a `type`.
* **Update**: `ARCHITECTURE.md` — removed client-specific and lab-specific narrative; the sudo section now states the client-dependency of agent-forward key-auth sudo as a deployment check rather than a fixed conclusion.
