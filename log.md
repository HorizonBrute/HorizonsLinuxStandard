# Directory Update Log

## 2026-07-24
* **Creation**: Bundle published as a host-neutral standard. Corpus extracted from a live hardened Fedora workstation and genericized — all hostnames, addresses, gateway MAC, WAN address, account names, key IDs, and personal identifiers replaced with angle-bracket placeholders. Host-specific material (audit trail, replaced configs, log exports, key material) deliberately excluded and retained only on the host.
* **Creation**: `CONTROLS.md` — prescriptive control set distilled from the decision log, ordered so each control's recovery path exists before the control that could remove it.
* **Creation**: `README.md` — purpose, placeholder glossary, setup procedure, and the `/root/<hostname>_security_config/` host-corpus convention for keeping per-host configuration and change log separate from the standard.
* **Creation**: `index.md`, `log.md` — OKF bundle index and history.
* **Update**: `SECURITY-DECISIONS.md` renamed to `DECISIONS.md`; all documents given OKF v0.2 YAML frontmatter with a `type`.
* **Update**: `ARCHITECTURE.md` — removed client-specific and lab-specific narrative; the sudo section now states the client-dependency of agent-forward key-auth sudo as a deployment check rather than a fixed conclusion.
* **Update**: Restructured so the standard carries no deviations. `DECISIONS.md` (the source host's chronological log) removed from the bundle entirely — host history belongs in that host's own record at `/root/<hostname>_security_config/`. Replaced by `RATIONALE.md`, keyed to control IDs, carrying the why / alternatives-rejected / caveats / rollback with no chronology and no host events.
* **Update**: `CONTROLS.md` — removed the *Accepted deviations* and *Anti-patterns* tables. Tightened the standard where the source host had been softening it: `X11Forwarding no` (C2.7), `usb-storage` blacklisted (C4.2), agent forwarding off by default (C2.6), `/var/log` non-group-writable (C6.4), container ports bound to loopback (C8.3), separate `/tmp` (C4.6). Added C1.6 for scoped first-key onboarding. Added a *Deviating from this standard* section defining the host-side register format.
* **Update**: `ARCHITECTURE.md` — dropped all `D###` cross-references and the deviations paragraph; escalation section reframed as a deployment check rather than a host conclusion.
* **Update**: Key-auth sudo restored as the standard's required escalation mechanism (C3.5) — it had been written defensively, with scoped `NOPASSWD` as a general fallback, which imported one host's client problem into the baseline. Scoped `NOPASSWD` is now explicitly the authorization layer for unattended service accounts only (C3.6). Agent forwarding is on and `Match Group`-scoped (C2.6) because C3 requires it. Added a **client requirements** section — `IdentitiesOnly`, explicit `IdentityFile`, named `Host` aliases — since client misconfiguration is the usual reason deployments abandon key-auth sudo.
* **Update**: Host corpus convention is `/root/<hostname>_security_config/`.
* **Update**: Framing broadened from single-owner workstation to an organizational baseline.

