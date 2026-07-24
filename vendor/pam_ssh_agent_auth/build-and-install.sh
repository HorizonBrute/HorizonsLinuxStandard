#!/usr/bin/env bash
# Build + install pam_ssh_agent_auth from Debian's verified source, then wire sudo PAM.
# Idempotent. Source of truth = ./src (offline); falls back to snapshot.debian.org if absent.
# Provenance: Debian src pkg pam-ssh-agent-auth 0.10.3-11, GPG-signed (Petter Reinholdtsen,
# fpr 3AC7B2E3ACA5DF8778F1D827111D6B29EE4E02F9). See PROVENANCE.md.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/src"
ORIG=pam-ssh-agent-auth_0.10.3.orig.tar.bz2
DEB=pam-ssh-agent-auth_0.10.3-11.debian.tar.xz
ORIG_SHA=3c53d358d6eaed1b211239df017c27c6f9970995d14102ae67bae16d4f47a763
DEB_SHA=7058e30d9089925630731db2face75816636b7a2be0b5b2ec7da49d575b76ace
LIBDIR="$(. /etc/os-release 2>/dev/null; case "${ID:-}${ID_LIKE:-}" in *debian*|*ubuntu*) echo "/usr/lib/$(uname -m)-linux-gnu/security";; *) echo /usr/lib64/security;; esac)"
MODULE="$LIBDIR/pam_ssh_agent_auth.so"
KEYDIR=/etc/security/sudo_authorized_keys.d
PAMSUDO=/etc/pam.d/sudo
PAMLINE='auth       sufficient   pam_ssh_agent_auth.so file=/etc/security/sudo_authorized_keys.d/%u.pub'

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

pkg(){ # install build deps via whatever package manager exists
  if command -v dnf >/dev/null; then dnf -y install gcc make openssl-devel pam-devel bzip2 xz tar
  elif command -v apt-get >/dev/null; then apt-get update && apt-get -y install gcc make libssl-dev libpam0g-dev bzip2 xz-utils tar
  elif command -v zypper >/dev/null; then zypper -n install gcc make libopenssl-devel pam-devel bzip2 xz tar
  elif command -v pacman >/dev/null; then pacman -Sy --noconfirm gcc make openssl pam bzip2 xz tar
  else echo "no known package manager" >&2; exit 1; fi
}

fetch(){ # populate $SRC from snapshot.debian.org if the tarballs are missing
  mkdir -p "$SRC"
  local b=https://snapshot.debian.org/file
  [ -f "$SRC/$ORIG" ] || curl -fsSL -o "$SRC/$ORIG" "$b/a4482a050fdad1d012427e45799564136708cf6b"
  [ -f "$SRC/$DEB"  ] || curl -fsSL -o "$SRC/$DEB"  "$b/1d1049455ac9d30fdf2c24dd663e4d5e5e8d178c"
}

verify(){ echo "$ORIG_SHA  $SRC/$ORIG" | sha256sum -c -; echo "$DEB_SHA  $SRC/$DEB" | sha256sum -c -; }

build(){
  local wd; wd="$(mktemp -d)"; trap 'rm -rf "$wd"' RETURN
  tar xjf "$SRC/$ORIG" -C "$wd"
  local d; d="$wd/$(ls "$wd")"
  tar xJf "$SRC/$DEB" -C "$d"
  ( cd "$d"
    while read -r p; do [ -n "$p" ] && patch -p1 --no-backup-if-mismatch -i "debian/patches/$p" >/dev/null; done < debian/patches/series
    export CFLAGS="-O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fno-strict-aliasing -std=gnu17 -Wno-error=implicit-function-declaration -Wno-error=implicit-int"
    export LDFLAGS="-Wl,-z,relro,-z,now"
    ./configure --libexecdir="$LIBDIR" --with-mantype=man --without-openssl-header-check >/dev/null
    make >/dev/null
    install -m 0755 -o root -g root pam_ssh_agent_auth.so "$MODULE"
  )
  command -v restorecon >/dev/null && restorecon -v "$MODULE" || true
}

wire(){
  install -d -m 0755 "$KEYDIR"
  [ -f "$PAMSUDO" ] || { echo "no $PAMSUDO" >&2; exit 1; }
  if ! grep -q pam_ssh_agent_auth.so "$PAMSUDO"; then
    cp -a "$PAMSUDO" "$PAMSUDO.pre-psaa.bak"
    # prepend as FIRST auth line; password stack remains as fallback (sufficient)
    awk -v line="$PAMLINE" '
      BEGIN{done=0}
      /^auth/ && !done {print "# Sudo-through-SSH-Key-Auth: verify caller SSH-agent key first; fall through to password.";
                        print line; done=1}
      {print}' "$PAMSUDO" > "$PAMSUDO.new"
    mv "$PAMSUDO.new" "$PAMSUDO"
  fi
  # sudo must keep SSH_AUTH_SOCK across env_reset for the module to see the agent
  grep -rqs 'env_keep.*SSH_AUTH_SOCK' /etc/sudoers /etc/sudoers.d 2>/dev/null \
    || echo 'Defaults env_keep += "SSH_AUTH_SOCK"' | (visudo -cf - >/dev/null 2>&1 && \
         install -m 0440 /dev/stdin /etc/sudoers.d/45-secbase-ssh-agent-env <<<'Defaults env_keep += "SSH_AUTH_SOCK"')
}

pkg; fetch; verify; build; wire
echo "[+] installed $MODULE and wired $PAMSUDO"
echo "    NOTE: sudo -n (non-interactive) bypasses PAM auth; test with a real tty or 'sudo cmd </dev/null'."
