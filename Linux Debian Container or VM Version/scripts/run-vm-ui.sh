#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PATH="$ROOT_DIR/bin:$PATH"

cd "$ROOT_DIR"
exec python3 "$ROOT_DIR/scanner_web.py" --host 0.0.0.0 --port "${SCANNER_PORT:-8788}"

