#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    echo "Docker Compose is missing. Install the Docker Compose plugin, then rerun." >&2
    exit 1
  fi
}

mkdir -p data/reports data/projectdiscovery

compose up --build -d

server_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
if [ -n "$server_ip" ]; then
  echo "Scanner UI: http://$server_ip:8788"
else
  echo "Scanner UI: http://SERVER-IP:8788"
fi
echo "Reports: $ROOT_DIR/data/reports"

