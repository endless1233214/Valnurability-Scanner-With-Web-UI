#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN_DIR="$ROOT_DIR/bin"
mkdir -p "$BIN_DIR" "$ROOT_DIR/reports"

need_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    echo "sudo is missing. Run this as root or install sudo." >&2
    exit 1
  fi
}

arch_name() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
  esac
}

latest_asset_url() {
  repo="$1"
  tool="$2"
  arch="$3"
  curl -fsSL "https://api.github.com/repos/projectdiscovery/$repo/releases/latest" \
    | grep "browser_download_url" \
    | grep "linux_${arch}.zip" \
    | sed -n 's/.*"browser_download_url": "\([^"]*\)".*/\1/p' \
    | head -n 1
}

install_pd_tool() {
  repo="$1"
  tool="$2"
  arch="$3"
  url=$(latest_asset_url "$repo" "$tool" "$arch")
  if [ -z "$url" ]; then
    echo "Could not find release asset for $tool linux_$arch" >&2
    exit 1
  fi

  tmp=$(mktemp)
  echo "[+] Downloading $tool from $url"
  curl -fsSL "$url" -o "$tmp"
  unzip -p "$tmp" "$tool" > "$BIN_DIR/$tool"
  chmod 0755 "$BIN_DIR/$tool"
  rm -f "$tmp"
}

if [ "$(uname -s)" != "Linux" ]; then
  echo "This setup script is for Debian/Linux VMs." >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This script expects Debian/Ubuntu/Raspberry Pi OS with apt-get." >&2
  exit 1
fi

echo "[+] Installing Debian packages..."
need_sudo apt-get update
need_sudo apt-get install -y --no-install-recommends ca-certificates curl iproute2 nmap python3 unzip

arch=$(arch_name)
install_pd_tool nuclei nuclei "$arch"
install_pd_tool httpx httpx "$arch"
install_pd_tool naabu naabu "$arch"

PATH="$BIN_DIR:$PATH"
echo "[+] Updating Nuclei templates..."
nuclei -update-templates || true

echo ""
echo "Done. Start the VM UI with:"
echo "  sh scripts/run-vm-ui.sh"

