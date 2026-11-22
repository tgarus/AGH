#!/usr/bin/env node
// Dev helper: wypisuje stan ASI przez API (login jak w demo-mock-scan.mjs).
import http from 'node:http';
const API = { host: process.env.ASI_API_HOST ?? '127.0.0.1', port: Number(process.env.ASI_API_PORT ?? 8080) };
const USER = process.env.ASI_ADMIN_USERNAME ?? 'admin';
const PASS = process.env.ASI_ADMIN_PASSWORD ?? 'ChangeMeNow_Admin123!';
function req(method, path, token, body, cookie) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const r = http.request({ ...API, path, method, headers: {
      'Content-Type': 'application/json',
      ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(cookie ? { Cookie: cookie } : {}),
    } }, (res) => {
      let b = ''; res.on('data', (c) => (b += c)); res.on('end', () => resolve({ status: res.statusCode, body: b, headers: res.headers }));
    });
    r.on('error', reject); if (data) r.write(data); r.end();
  });
}
const j = (r) => { try { return JSON.parse(r.body); } catch { return r.body; } };

const login = await req('POST', '/api/v1/auth/login', null, { username: USER, password: PASS });
console.log('login:', login.status, 'set-cookie:', JSON.stringify(login.headers['set-cookie'] ?? null));
if (login.status !== 200) process.exit(1);
const T = j(login).access_token;
const cookie = (login.headers['set-cookie'] ?? []).map((c) => c.split(';')[0]).join('; ');

// refresh z ciasteczkiem (jak przy odświeżeniu strony)
const ref = await req('POST', '/api/v1/auth/refresh', null, null, cookie);
console.log('refresh with cookie:', ref.status, ref.status === 200 ? 'OK (new token)' : j(ref));

for (const [label, path] of [
  ['healthz', '/api/v1/healthz'],
  ['workers', '/api/v1/workers'],
  ['scans', '/api/v1/scans?per_page=10'],
  ['signatures', '/api/v1/signatures?per_page=5'],
  ['dashboard', '/api/v1/dashboard/summary'],
]) {
  const r = await req('GET', path, T);
  const d = j(r);
  if (label === 'scans') {
    console.log(`scans (${r.status}):`, (d.items ?? []).map((s) => `${s.id.slice(0, 8)} ${s.status} chunks=${s.completed_chunks}/${s.total_chunks} targets=${s.total_targets} err=${s.last_error ?? '-'}`).join('\n  '));
  } else if (label === 'signatures') {
    console.log(`signatures (${r.status}): total=${d.total ?? d.items?.length} first=${(d.items ?? []).map((x) => x.name).join(', ')}`);
  } else {
    console.log(`${label} (${r.status}):`, JSON.stringify(d).slice(0, 400));
  }
}

// znajdź „wiszący” skan i go zatrzymaj (pausing/queued/running starszy niż bieżący)
const scans = j(await req('GET', '/api/v1/scans?per_page=10', T));
const active = (scans.items ?? []).find((s) => ['queued', 'running', 'pausing', 'paused'].includes(s.status));
if (active) {
  const det = j(await req('GET', `/api/v1/scans/${active.id}`, T));
  console.log(`active scan ${active.id.slice(0, 8)}: status=${det.status} group=${det.asset_group_id} err=${det.last_error ?? '-'}`);
  const grp = j(await req('GET', `/api/v1/asset-groups/${det.asset_group_id}`, T));
  const tgts = (grp.targets ?? []).map((t) => t.value).slice(0, 5);
  console.log(`  group=${grp.name} targets=${(grp.targets ?? []).length} sample=${tgts.join(', ')}`);
  if (process.argv.includes('--stop')) {
    const stop = await req('POST', `/api/v1/scans/${active.id}/stop`, T);
    console.log(`  stop → ${stop.status} ${stop.body.slice(0, 120)}`);
  } else {
    console.log('  (uruchom z --stop, aby zatrzymać)');
  }
} else {
  console.log('no active scans');
}
