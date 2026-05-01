#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN_DIR="$ROOT_DIR/bin"
PATH="$BIN_DIR:$PATH"

mkdir -p "$BIN_DIR" "$ROOT_DIR/reports"

say() {
  printf '%s\n' "$*"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

need_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif have sudo; then
    sudo "$@"
  else
    say "Missing sudo. Please install dependencies manually: $*"
    return 1
  fi
}

install_system_tools() {
  os=$(uname -s 2>/dev/null || echo unknown)

  case "$os" in
    Darwin)
      if ! have brew; then
        say "Homebrew is required on macOS. Install it from https://brew.sh, then rerun this script."
        exit 1
      fi
      say "[+] Installing system tools with Homebrew..."
      brew install nmap go
      ;;
    Linux)
      if have apt-get; then
        say "[+] Installing system tools with apt..."
        need_sudo apt-get update
        need_sudo apt-get install -y nmap golang-go git ca-certificates
      elif have dnf; then
        say "[+] Installing system tools with dnf..."
        need_sudo dnf install -y nmap golang git ca-certificates
      elif have yum; then
        say "[+] Installing system tools with yum..."
        need_sudo yum install -y nmap golang git ca-certificates
      elif have zypper; then
        say "[+] Installing system tools with zypper..."
        need_sudo zypper --non-interactive install nmap go git ca-certificates
      elif have pacman; then
        say "[+] Installing system tools with pacman..."
        need_sudo pacman -Sy --needed nmap go git ca-certificates
      else
        say "Unsupported Linux package manager. Install nmap, go, git, and ca-certificates, then rerun."
        exit 1
      fi
      ;;
    *)
      say "Unsupported OS: $os"
      exit 1
      ;;
  esac
}

install_go_tool() {
  name="$1"
  module="$2"

  if have "$name"; then
    say "[+] $name already available."
    return 0
  fi

  if ! have go; then
    say "go is missing, cannot install $name."
    return 1
  fi

  say "[+] Installing $name into $BIN_DIR..."
  if GOBIN="$BIN_DIR" go install "$module"; then
    say "[+] Installed $name."
  else
    say "[!] Could not install $name. The scanner can still run, but related checks may be skipped."
  fi
}

check_versions() {
  say ""
  say "Tool check:"
  for tool in nmap nuclei httpx naabu python3; do
    if have "$tool"; then
      printf '  %-8s %s\n' "$tool" "$(command -v "$tool")"
    else
      printf '  %-8s missing\n' "$tool"
    fi
  done
}

case "${1:-}" in
  --check)
    check_versions
    exit 0
    ;;
  --help|-h)
    cat <<EOF
Usage:
  sh setup_scanner.sh          install scanner dependencies
  sh setup_scanner.sh --check  show tool paths

Installs Nmap and Go through your OS package manager, then installs Nuclei,
httpx, and naabu into ./bin using go install.
EOF
    exit 0
    ;;
esac

install_system_tools
install_go_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
install_go_tool httpx github.com/projectdiscovery/httpx/cmd/httpx@latest
install_go_tool naabu github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

if have nuclei; then
  say "[+] Updating Nuclei templates..."
  nuclei -update-templates || say "[!] Template update failed. You can retry later with: nuclei -update-templates"
fi

check_versions
say ""
say "Done. Start the UI with:"
say "  sh run_web.sh"

