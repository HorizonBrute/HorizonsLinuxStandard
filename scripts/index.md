# Scripts

* [harden.sh](harden.sh) - Idempotent CIS Level 1 layer: sysctl, module blacklists, password and lockout policy, auditd rules, SSH hardening, firewall baseline. Read before running.
* [netmode.sh](netmode.sh) - Switches the host's outbound egress backend (raw / Tor / other), with validation and revert.
* [toggle_tor.sh](toggle_tor.sh) - Enables or disables transparent system-wide torification behind a systemd dead-man auto-revert. Confirms a Tor exit IP and a live SSH session before keeping the change.
* [pam-sudo-key-auth.scaffold](pam-sudo-key-auth.scaffold) - Reference `/etc/pam.d/sudo` stack placing `pam_ssh_agent_auth` first as `sufficient`, with the password stack retained below as fallback.
