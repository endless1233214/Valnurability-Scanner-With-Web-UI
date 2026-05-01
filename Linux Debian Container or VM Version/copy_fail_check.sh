#!/bin/sh
set -eu

section() {
  printf '\n== %s ==\n' "$1"
}

pass() {
  printf '[OK] %s\n' "$1"
}

warn() {
  printf '[WARN] %s\n' "$1"
}

info() {
  printf '[INFO] %s\n' "$1"
}

section "Host"
os_name="$(uname -s 2>/dev/null || echo unknown)"
printf 'OS: %s\n' "$os_name"
printf 'Kernel: '
uname -r 2>/dev/null || true

if [ "$os_name" != "Linux" ]; then
  pass "This is not Linux, so CVE-2026-31431 does not apply to this kernel."
  exit 0
fi

if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  printf 'Distro: %s\n' "${PRETTY_NAME:-unknown}"
fi

section "algif_aead module state"
loaded="unknown"
if [ -r /proc/modules ]; then
  if grep -qE '^algif_aead ' /proc/modules; then
    loaded="yes"
    warn "algif_aead is currently loaded."
  else
    loaded="no"
    pass "algif_aead is not currently loaded."
  fi
else
  warn "Cannot read /proc/modules."
fi

blocked="no"
if grep -RhsE '^[[:space:]]*(install[[:space:]]+algif_aead[[:space:]]+/(usr/)?bin/false|blacklist[[:space:]]+algif_aead)\b' \
  /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d /lib/modprobe.d /usr/lib/modprobe.d 2>/dev/null; then
  blocked="yes"
  pass "Found a modprobe rule that blocks algif_aead."
else
  warn "No modprobe block rule for algif_aead was found."
fi

if command -v modprobe >/dev/null 2>&1; then
  info "modprobe dry-run result:"
  modprobe -n -v algif_aead 2>&1 | sed 's/^/  /' || true
else
  warn "modprobe is not installed or not in PATH."
fi

section "Kernel config hint"
config_found="no"
if [ -r "/boot/config-$(uname -r)" ]; then
  config_found="yes"
  grep -E '^CONFIG_CRYPTO_USER_API_AEAD=' "/boot/config-$(uname -r)" || true
elif [ -r /proc/config.gz ] && command -v gzip >/dev/null 2>&1; then
  config_found="yes"
  gzip -dc /proc/config.gz | grep -E '^CONFIG_CRYPTO_USER_API_AEAD=' || true
fi

if [ "$config_found" = "no" ]; then
  info "Kernel config was not readable. This is common on some distros."
fi

section "AF_ALG socket hint"
if command -v ss >/dev/null 2>&1; then
  if ss -xa 2>/dev/null | grep -i 'alg' >/tmp/copy_fail_afalg_check.$$ 2>/dev/null; then
    warn "AF_ALG-like sockets are visible:"
    sed 's/^/  /' /tmp/copy_fail_afalg_check.$$
  else
    pass "No AF_ALG-like sockets were visible through ss."
  fi
  rm -f /tmp/copy_fail_afalg_check.$$
else
  info "ss is unavailable; skipping socket check."
fi

section "Package/update hints"
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${Package} ${Version}\n' kmod 'linux-image*' 2>/dev/null | sed 's/^/  /' || true
  info "For Debian/Ubuntu/Raspberry Pi OS, run: sudo apt update && sudo apt full-upgrade && sudo reboot"
elif command -v rpm >/dev/null 2>&1; then
  rpm -qa 'kernel*' 'kmod*' 2>/dev/null | sort | sed 's/^/  /' || true
  info "For RHEL/Fedora/Rocky/Alma, run: sudo dnf upgrade --refresh && sudo reboot"
elif command -v zypper >/dev/null 2>&1; then
  zypper se -si kernel-default kmod 2>/dev/null | sed 's/^/  /' || true
  info "For SUSE, run: sudo zypper refresh && sudo zypper patch && sudo reboot"
elif command -v pacman >/dev/null 2>&1; then
  pacman -Q linux linux-lts 2>/dev/null | sed 's/^/  /' || true
  info "For Arch, run: sudo pacman -Syu && sudo reboot"
else
  info "No common package manager detected."
fi

section "Verdict"
if [ "$blocked" = "yes" ] && [ "$loaded" = "no" ]; then
  pass "Temporary mitigation appears active: algif_aead is blocked and not loaded."
  info "Still install the fixed kernel package when available."
elif [ "$blocked" = "yes" ] && [ "$loaded" = "yes" ]; then
  warn "A block rule exists, but algif_aead is still loaded. Reboot or unload it."
else
  warn "Assume this Linux host is exposed until patched or mitigated."
  info "Use copy_fail_mitigate.sh --apply if you cannot patch right now."
fi

