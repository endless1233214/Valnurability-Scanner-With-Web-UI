#!/bin/sh
set -eu

mkdir -p /opt/scanner/reports /scanner-data

if [ "${NUCLEI_UPDATE_ON_START:-false}" = "true" ]; then
  nuclei -update-templates || true
fi

exec python3 /opt/scanner/scanner_web.py \
  --host "${SCANNER_HOST:-0.0.0.0}" \
  --port "${SCANNER_PORT:-8788}"

