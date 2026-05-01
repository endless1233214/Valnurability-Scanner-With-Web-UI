#!/bin/sh
set -eu

CONF=/etc/modprobe.d/disable-algif_aead-copyfail.conf

if [ "$(uname -s 2>/dev/null || echo unknown)" != "Linux" ]; then
  echo "This is not Linux. Nothing to mitigate for CVE-2026-31431."
  exit 0
fi

if [ "${1:-}" != "--apply" ]; then
  cat <<EOF
Dry run only. This script will apply the temporary Copy Fail mitigation:

  1. Write:
     $CONF

     with:
     install algif_aead /bin/false

  2. Try to unload algif_aead if it is currently loaded.

Run this on the Linux host with:

  sudo sh copy_fail_mitigate.sh --apply

Patch and reboot are still the final fix.
EOF
  exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Please rerun with sudo/root: sudo sh copy_fail_mitigate.sh --apply" >&2
  exit 1
fi

mkdir -p /etc/modprobe.d
printf '%s\n' 'install algif_aead /bin/false' > "$CONF"
echo "Wrote $CONF"

if command -v modprobe >/dev/null 2>&1; then
  modprobe -r algif_aead 2>/dev/null || true
else
  rmmod algif_aead 2>/dev/null || true
fi

if grep -qE '^algif_aead ' /proc/modules 2>/dev/null; then
  echo "algif_aead is still loaded. Reboot this host when you can."
  exit 2
fi

echo "algif_aead is blocked and not currently loaded."
echo "Now install the fixed kernel package when your distro provides it."

