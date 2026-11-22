#!/usr/bin/env bash
# Dev helper: diagnostyka lokalnego DefectDojo przez API v2 z WSL (klucz z /tmp/dd-token.txt).
# Użycie: dev-dd-check.sh [users|products|findings|engagements|mitigate <finding_id>]
set -u
K=$(cat /tmp/dd-token.txt 2>/dev/null || awk '/Generated token/ {print $3}' /tmp/dd-init2.log | head -1)
MODE="${1:-users}"
FID="${2:-1}"
K="$K" MODE="$MODE" FID="$FID" python3 -c "
import os, json, urllib.request, urllib.error
key = os.environ['K']; mode = os.environ['MODE']; fid = os.environ['FID']
H = {'Authorization': 'Token ' + key, 'Content-Type': 'application/json'}
def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request('http://127.0.0.1:8081' + path, data=data, headers=H, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=30)
        return r.status, r.read()[:250]
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:250]
if mode == 'mitigate':
    print('PATCH finding', fid, call('PATCH', '/api/v2/findings/' + fid + '/', {'active': False, 'false_p': True, 'tags': ['asi', 'soc-triaged']}))
    print('GET finding', fid, call('GET', '/api/v2/findings/' + fid + '/'))
    raise SystemExit
path = {'users': '/api/v2/users/?limit=3', 'products': '/api/v2/products/?limit=10',
        'findings': '/api/v2/findings/?limit=10', 'engagements': '/api/v2/engagements/?limit=10'}.get(mode, '/api/v2/users/?limit=3')
req = urllib.request.Request('http://127.0.0.1:8081' + path, headers={'Authorization': 'Token ' + key})
try:
    r = urllib.request.urlopen(req, timeout=15)
    d = json.loads(r.read())
    print(mode, '->', r.status, 'count=', d.get('count'))
    for it in (d.get('results') or [])[:10]:
        if mode == 'findings':
            print('  finding', it.get('id'), it.get('title'), '| sev', it.get('severity'), '| status', it.get('status'), '| unique', it.get('unique_id_from_tool'), '| tags', it.get('tags'))
        elif mode == 'products':
            print('  product', it.get('id'), it.get('name'))
        elif mode == 'engagements':
            print('  engagement', it.get('id'), it.get('name'), '| product', it.get('product'))
        else:
            print('  user', it.get('id'), it.get('username'))
except urllib.error.HTTPError as e:
    print(mode, '->', e.code, e.read()[:150])
except Exception as e:
    print(mode, '-> ERR', e)
"
