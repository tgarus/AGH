#!/usr/bin/env bash
# Dev helper: sprawdza dostępność lokalnego sinka webhookowego z WSL (port 19999).
set -u
python3 -c "
import urllib.request, time
t0 = time.time()
try:
    r = urllib.request.urlopen('http://127.0.0.1:19999/hook', timeout=8)
    print('wsl 127.0.0.1:19999 ->', r.status, round(time.time()-t0, 2), 's')
except Exception as e:
    print('wsl 127.0.0.1:19999 -> ERR', type(e).__name__, e, round(time.time()-t0, 2), 's')
"
