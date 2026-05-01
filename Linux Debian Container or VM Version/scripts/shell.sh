#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

if docker compose version >/dev/null 2>&1; then
  docker compose exec scanner sh
else
  docker-compose exec scanner sh
fi

