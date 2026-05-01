#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PATH="$ROOT_DIR/bin:$PATH"

exec python3 "$ROOT_DIR/scanner_web.py" "$@"
