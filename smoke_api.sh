#!/bin/bash
# Tymczasowy smoke-test: start asi-api (no-db tryb lub z .env), healthz/readyz/openapi, kill.
cd /mnt/c/Users/tgarus/AGH
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_DIR="$HOME/.cache/asi-target"
export ASI_BIND_ADDR="127.0.0.1:8080"
export ASI_COOKIE_SECURE="0"
export ASI_LOG_FORMAT="pretty"
B="$CARGO_TARGET_DIR/debug/asi-api"
"$B" > /mnt/c/Users/tgarus/AGH/smoke_api.log 2>&1 &
PID=$!
sleep 5
echo "--- healthz ---"
curl -s http://127.0.0.1:8080/api/v1/healthz
echo
echo "--- readyz ---"
curl -s http://127.0.0.1:8080/api/v1/readyz
echo
echo "--- openapi head ---"
curl -s http://127.0.0.1:8080/api/v1/openapi.json | head -c 200
echo
echo "--- login (bez DB -> oczekiwany blad 503) ---"
curl -s -X POST http://127.0.0.1:8080/api/v1/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"x"}'
echo
kill $PID 2>/dev/null
wait $PID 2>/dev/null
echo "--- api log tail ---"
tail -6 /mnt/c/Users/tgarus/AGH/smoke_api.log
rm -f /mnt/c/Users/tgarus/AGH/smoke_api.log
