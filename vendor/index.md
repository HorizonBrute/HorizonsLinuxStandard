# Vendor

Third-party material with established provenance.

* [pam_ssh_agent_auth/PROVENANCE.md](pam_ssh_agent_auth/PROVENANCE.md) - Source, full authentication chain, and build procedure for `pam_ssh_agent_auth`, which is not packaged by Fedora or EPEL.
* [pam_ssh_agent_auth/build-and-install.sh](pam_ssh_agent_auth/build-and-install.sh) - Idempotent build. Fetches the signed Debian source from snapshot.debian.org by pinned hash if absent, verifies, builds, installs.
* [pam_ssh_agent_auth/SHA256SUMS](pam_ssh_agent_auth/SHA256SUMS) - Expected digests for the upstream tarballs.
* [selinux/secbase_onboard.te](selinux/secbase_onboard.te) - `dontaudit` policy module suppressing benign PID1 audit noise when the onboarding path-unit probes `authorized_keys`. Grants nothing.

The compiled module and upstream source tarballs are intentionally not committed — `build-and-install.sh` retrieves and verifies them.
