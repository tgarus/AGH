#!/usr/bin/env node
// Dev helper (tylko lokalne testy ręczne): akcje admina przez ASI API.
// Użycie:
//   node scripts/dev-admin.mjs sync                 — POST /signatures/sync (wbudowane + repo GitHub)
//   node scripts/dev-admin.mjs worker-token         — POST /workers/tokens (nowy token, drukowany lokalnie)
//   node scripts/dev-admin.mjs dd <base_url> <api_key> [asi_public_url] — PUT konfiguracji DefectDojo + test-connection
//   node scripts/dev-admin.mjs dd-sync              — POST /integrations/defectdojo/sync (ręczny push)
//   node scripts/dev-admin.mjs dd-outbox            — GET kolejki dd_outbox
//   node scripts/dev-admin.mjs webhook <url> <secret> — POST kanału webhook (HMAC)
//   node scripts/dev-admin.mjs webhook-test <id>    — POST test-delivery kanału
//   node scripts/dev-admin.mjs deliveries           — GET ostatnich delivery powiadomień
import http from 'node:http';

const API = { host: process.env.ASI_API_HOST ?? '127.0.0.1', port: Number(process.env.ASI_API_PORT ?? 8080) };
const USER = process.env.ASI_ADMIN_USERNAME ?? 'admin';
const PASS = process.env.ASI_ADMIN_PASSWORD ?? 'ChangeMeNow_Admin123!';

function req(method, path, token, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const r = http.request(
      { ...API, path, method, headers: {
        'Content-Type': 'application/json',
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      } },
      (res) => { let b = ''; res.on('data', (c) => (b += c)); res.on('end', () => resolve({ status: res.statusCode, body: b })); },
    );
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}
const j = (r) => { try { return JSON.parse(r.body); } catch { return r.body; } };

const login = await req('POST', '/api/v1/auth/login', null, { username: USER, password: PASS });
if (login.status !== 200) { console.error('login failed', login.status, login.body); process.exit(1); }
const T = j(login).access_token;

const cmd = process.argv[2];
const out = (label, r, n = 400) => console.log(`${label} → ${r.status}`, String(typeof r.body === 'string' ? r.body : JSON.stringify(r.body)).slice(0, n));

if (cmd === 'sync') {
  const r = await req('POST', '/api/v1/signatures/sync', T, {});
  out('sync', r, 500);
  out('signatures total', await req('GET', '/api/v1/signatures?per_page=1', T), 200);
} else if (cmd === 'worker-token') {
  const r = await req('POST', '/api/v1/workers/tokens', T, { name: `wsl-dev-${process.pid}`, segment_tag: 'mock-lab', max_concurrency: 2 });
  const d = j(r);
  console.log(`worker-token → ${r.status} name=${d.worker?.name} token=${d.token ?? ''}`);
} else if (cmd === 'dd') {
  // sekrety tylko przez env (ASI_DD_URL / ASI_DD_KEY), nigdy jako argument komendy
  const [baseUrl, apiKey, asiUrl = 'http://localhost:5173'] = process.argv[3] === '--env'
    ? [process.env.ASI_DD_URL, process.env.ASI_DD_KEY, process.env.ASI_DD_PUBLIC_URL ?? 'http://localhost:5173']
    : process.argv.slice(3);
  if (!baseUrl || !apiKey) { console.error('dd: podaj --env (ASI_DD_URL, ASI_DD_KEY) albo argumenty base_url api_key'); process.exit(2); }
  out('dd PUT', await req('PUT', '/api/v1/integrations/defectdojo', T, {
    enabled: true, base_url: baseUrl, api_key: apiKey, asi_public_url: asiUrl,
    finding_scope: 'changes', auto_push: true, pull_interval_minutes: 1,
  }), 300);
  out('dd test-connection', await req('POST', '/api/v1/integrations/defectdojo/test-connection', T, {}), 300);
} else if (cmd === 'dd-sync') {
  out('dd sync (202)', await req('POST', '/api/v1/integrations/defectdojo/sync', T, {}), 200);
} else if (cmd === 'dd-push') {
  out('dd push diff', await req('POST', `/api/v1/integrations/defectdojo/push/${process.argv[3]}`, T, {}), 500);
} else if (cmd === 'dd-outbox') {
  out('dd outbox', await req('GET', '/api/v1/integrations/defectdojo/outbox?per_page=50', T), 4000);
} else if (cmd === 'webhook') {
  // sekret tylko przez env ASI_WEBHOOK_SECRET (domyślnie wartość dev, nie sekret produkcyjny)
  const url = process.argv[3] ?? 'http://127.0.0.1:19999/hook';
  const secret = process.env.ASI_WEBHOOK_SECRET ?? 'dev-hmac-secret-not-a-real-one';
  out('webhook create', await req('POST', '/api/v1/notifications/channels', T, {
    name: `local-test-${process.pid}`, channel_type: 'webhook_json', asset_group_id: null,
    notify_on_confirmed: true, notify_on_variance: true, is_enabled: true,
    config_public: { url },
    secret,
  }), 300);
} else if (cmd === 'webhook-test') {
  out('webhook test', await req('POST', `/api/v1/notifications/channels/${process.argv[3]}/test`, T, {}), 300);
} else if (cmd === 'deliveries') {
  out('deliveries', await req('GET', '/api/v1/notifications/deliveries?per_page=10', T), 800);
} else if (cmd === 'channels') {
  out('channels', await req('GET', '/api/v1/notifications/channels', T), 600);
} else if (cmd === 'groups') {
  out('groups', await req('GET', '/api/v1/asset-groups?per_page=20', T), 900);
} else if (cmd === 'diffs') {
  out('diffs', await req('GET', `/api/v1/diffs?per_page=20${process.argv[3] ? `&asset_group_id=${process.argv[3]}` : ''}`, T), 1500);
} else if (cmd === 'scans') {
  out('scans', await req('GET', '/api/v1/scans?per_page=10', T), 900);
} else {
  console.log('unknown command; see header');
}
