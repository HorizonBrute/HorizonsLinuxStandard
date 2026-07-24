---
type: Provenance
title: pam_ssh_agent_auth — provenance
description: Source, authentication chain, and build procedure for the vendored pam_ssh_agent_auth module, which is not packaged by Fedora or EPEL.
tags: [provenance, supply-chain, pam, sudo, vendored]
status: stable
resource: https://github.com/jbeverly/pam_ssh_agent_auth
---

# pam_ssh_agent_auth — provenance

Module not packaged by Fedora/EPEL/RHEL (verified: koji, dist-git, EPEL 8/9/10, EL8/EL7 vaults).
Built from Debian's maintained, signed source package.

## Source
- Debian source pkg: `pam-ssh-agent-auth` 0.10.3-11 (binary `libpam-ssh-agent-auth`).
- Upstream: https://github.com/jbeverly/pam_ssh_agent_auth (0.10.3, 2012) + Debian patch series.
- Obtained via snapshot.debian.org (by-hash), cross-checked against the signed `.dsc`.

## Authentication chain (all verified)
- snapshot manifest sha1 == downloaded files.
- `.dsc` Checksums-Sha256 == independent sha256 of both tarballs:
  - orig.tar.bz2  `3c53d358d6eaed1b211239df017c27c6f9970995d14102ae67bae16d4f47a763`
  - debian.tar.xz `7058e30d9089925630731db2face75816636b7a2be0b5b2ec7da49d575b76ace`
- `.dsc` PGP signature: GOOD — Petter Reinholdtsen <pere@debian.org>
  - signer fpr `3AC7 B2E3 ACA5 DF87 78F1 D827 111D 6B29 EE4E 02F9`
  - confirmed present in Debian's official developer DB (db.debian.org/fetchkey.cgi).

## Build
- 8 Debian patches applied (OpenSSL-1.1/3 compat, gcc-14, ECDSA segfault, sha256 fp, ed25519 clean).
- Configure: `--libexecdir=<security libdir> --with-mantype=man --without-openssl-header-check`.
- Hardened CFLAGS (FORTIFY, stack-protector-strong, PIC) + `-Wl,-z,relro,-z,now` (full RELRO/BIND_NOW).
- `-Wno-error=implicit-function-declaration` only to pass configure's own stub under gcc 16.
- Links cleanly vs system libcrypto.so.3 + libpam.so.0; exports pam_sm_authenticate/pam_sm_setcred.
- Built artifact sha256 is host/toolchain-specific; rebuild with build-and-install.sh, do not trust a copied .so blindly.

## Rebuild / install
`./build-and-install.sh` (idempotent). Uses ./src offline; else re-fetches+verifies from snapshot.

## Notes
- `%u` in `file=` expands to the user being authenticated; for sudo that is the INVOKING user
  at auth time → per-caller `/etc/security/sudo_authorized_keys.d/%u.pub` is correct.
- `sudo -n` (non-interactive) short-circuits before the PAM auth stack — it does NOT exercise
  this module. Test with a tty or `sudo <cmd> </dev/null`.
