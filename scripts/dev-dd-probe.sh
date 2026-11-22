#!/usr/bin/env bash
# Dev helper: zapewnia domyślny product_type w lokalnym DD i tworzy produkt testowy (klucz z /tmp/dd-token.txt).
set -u
K=$(cat /tmp/dd-token.txt 2>/dev/null || echo "")
K="$K" python3 -c "
import os, json, time, urllib.request, urllib.error
key = os.environ['K']
H = {'Authorization': 'Token ' + key, 'Content-Type': 'application/json'}
def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request('http://127.0.0.1:8081' + path, data=data, headers=H, method=method)
    t0 = time.time()
    try:
        r = urllib.request.urlopen(req, timeout=30)
        return r.status, r.read()[:200], round(time.time()-t0, 2)
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:200], round(time.time()-t0, 2)
    except Exception as e:
        return 'ERR', str(e), round(time.time()-t0, 2)
print('GET product_types:', call('GET', '/api/v2/product_types/?limit=5'))
s, b, dt = call('POST', '/api/v2/product_types/', {'name': 'AGH Default', 'description': 'ASI default product type'})
print('POST product_type:', s, b, dt, 's')
s, b, dt = call('GET', '/api/v2/product_types/?limit=5')
print('GET product_types again:', s, b, dt, 's')
"
