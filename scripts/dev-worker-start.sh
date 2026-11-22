#!/usr/bin/env bash
# Dev helper: generuje token workera przez API i startuje asi-worker z tym tokenem.
# Token ląduje tylko w /tmp/asi-worker-token (poza repo), nie w komendzie.
set -u
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/asi-target}"
OUT=$(node scripts/dev-admin.mjs worker-token)
echo "$OUT" | grep -o 'token=[^ ]*' | cut -d= -f2 > /tmp/asi-worker-token
echo "token zapisany, bajtow: $(wc -c < /tmp/asi-worker-token)"
export ASI_WORKER_TOKEN="$(cat /tmp/asi-worker-token)"
exec cargo run -p asi-worker
