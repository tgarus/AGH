#!/usr/bin/env node
// Dev helper: lokalny odbiornik webhooków (sink) — loguje żądania do stdout i /tmp/asi-webhook-sink.log.
// Uruchom: node scripts/dev-webhook-sink.mjs  (port ASI_SINK_PORT, domyślnie 19999)
import http from 'node:http';
import fs from 'node:fs';

const port = Number(process.env.ASI_SINK_PORT ?? 19999);
const log = '/tmp/asi-webhook-sink.log';
http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    const asiHeaders = Object.entries(req.headers).filter(([k]) => k.startsWith('x-asi')).map(([k, v]) => `${k}=${v}`).join(' ');
    const line = `${new Date().toISOString()} ${req.method} ${req.url} ${asiHeaders} body=${body.slice(0, 220)}\n`;
    fs.appendFileSync(log, line);
    console.log(line.trim());
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"ok":true}');
  });
}).listen(port, '0.0.0.0', () => console.log(`webhook sink on :${port}, log: ${log}`));
