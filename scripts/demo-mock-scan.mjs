#!/usr/bin/env node
// Demo lokalne (dev): skanuje Docker Mock-Lab przez porty publikowane na 127.0.0.1
// i wypisuje wyniki z ASI API. Wymaga: make dev-up && make api (w WSL).
//
//   ASI_ADMIN_USERNAME=admin ASI_ADMIN_PASSWORD=... node scripts/demo-mock-scan.mjs
// (bez zmiennych użyje dev-owych wartości z .env.example — tylko lokalnie!)
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
const j = (r) => JSON.parse(r.body);

const login = await req('POST', '/api/v1/auth/login', null, { username: USER, password: PASS });
if (login.status !== 200) { console.error('login failed', login.status, login.body); process.exit(1); }
const T = j(login).access_token;

// ASI_DEMO_GROUP_ID=<uuid> — skanuj istniejącą grupę (do testu diffów między skanami)
const existingGid = process.env.ASI_DEMO_GROUP_ID ?? null;
let gid = existingGid;
let grpName = existingGid ?? '(nowa)';
if (!existingGid) {
  const suffix = Math.random().toString(36).slice(2, 8);
  const pol = j(await req('POST', '/api/v1/policies', T, {
    name: `mock-lab-ports-${suffix}`, port_spec: '18080,18081,18082,18443,18444,8888,9443,19099',
    discovery_tool: 'naabu', rate_pps: 500, per_ip_cooldown_ms: 100, subnet_concurrency: 4,
    kill_grace_seconds: 3, inactivity_threshold: Number(process.env.ASI_DEMO_THRESHOLD ?? 3), tarpit_port_threshold: 200, enable_nuclei: false,
    time_windows: { allowed_windows: [{ start: '00:00', end: '23:59', timezone: 'Europe/Warsaw' }] },
  }));
  const grp = j(await req('POST', '/api/v1/asset-groups', T, {
    name: `mock-loopback-${suffix}`, description: 'Docker Mock-Lab via 127.0.0.1 published ports',
    policy_id: pol.id, sampling_enabled: false,
  }));
  gid = grp.id;
  grpName = grp.name;
  await req('POST', `/api/v1/asset-groups/${gid}/targets`, T, { targets: [{ target_type: 'ip', value: '127.0.0.1' }] });
}

const pre = j(await req('POST', '/api/v1/scans/preflight', T, { asset_group_id: gid, window_minutes: 10 }));
console.log(`preflight: targets=${pre.total_targets} chunks=${pre.total_chunks} est=${pre.estimated_duration_seconds}s`);

const scan = j(await req('POST', '/api/v1/scans', T, { asset_group_id: gid, trigger_type: 'manual' }));
console.log(`scan ${scan.id} → ${scan.status} (grupa ${grpName} ${gid})`);

// poll statusu do zakończenia (max 5 min)
for (let i = 0; i < 60; i++) {
  await new Promise((r) => setTimeout(r, 5000));
  const s = j(await req('GET', `/api/v1/scans/${scan.id}`, T));
  if (['completed', 'failed', 'stopped'].includes(s.status)) {
    console.log(`scan ${s.status} (chunks ${s.completed_chunks}/${s.total_chunks})`);
    break;
  }
}

const hosts = j(await req('GET', `/api/v1/hosts?asset_group_id=${gid}&per_page=10`, T)).items ?? [];
console.log('hosty:', hosts.map((h) => `${h.ip_addr} ${h.status} ports=${h.open_port_count}`).join(' | '));
const svcs = j(await req('GET', `/api/v1/services?asset_group_id=${gid}&per_page=50`, T)).items ?? [];
for (const s of svcs) console.log(`  svc ${s.ip_addr}:${s.port}/${s.protocol} ${s.service ?? ''} ${s.version ?? ''} title="${s.title ?? ''}"`);
const diffs = (j(await req('GET', '/api/v1/diffs?per_page=100', T)).items ?? [])
  .filter((d) => hosts.some((h) => h.id === d.host_id));
console.log('diffy:', diffs.length);
for (const d of diffs.slice(0, 10)) console.log(`  ${d.ip_addr} ${d.event_kind} ${d.severity} ${JSON.stringify(d.bullet_items).slice(0, 160)}`);
console.log(`\nUI: http://localhost:5173  (zaloguj się jako admin) — zakładki Skany / Hosty i usługi / Diffy`);
