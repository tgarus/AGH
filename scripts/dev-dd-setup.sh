#!/usr/bin/env bash
# Dev helper: konfiguruje integrację DefectDojo w ASI API.
# Token DD bierze z logu `make dd-init` (/tmp/dd-init2.log) — sekret nie występuje w komendzie.
set -euo pipefail
DDKEY=$(cat /tmp/dd-token.txt 2>/dev/null || awk '/Generated token/ {print $3}' /tmp/dd-init2.log | head -1)
if [ -z "$DDKEY" ]; then echo "brak tokena w /tmp/dd-init2.log — najpierw: make dd-init" >&2; exit 1; fi
cd "$(dirname "$0")/.."
ASI_DD_URL="${ASI_DD_URL:-http://127.0.0.1:8081}" \
ASI_DD_KEY="$DDKEY" \
ASI_DD_PUBLIC_URL="${ASI_DD_PUBLIC_URL:-http://localhost:5173}" \
  node scripts/dev-admin.mjs dd --env
