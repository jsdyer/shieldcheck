import test from 'node:test';
import assert from 'node:assert/strict';
import http2 from 'node:http2';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createH2Fetch } from '../scripts/h2fetch.mjs';
import * as DNS from '../web/dns.mjs';

test('DoH over HTTP/2 against a local HTTP/2-only server (as CIRA and Quad9 require)', async (t) => {
  const dir = mkdtempSync(path.join(tmpdir(), 'h2-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem'), '-days', '1', '-subj', '/CN=localhost'], { stdio: 'ignore' });
  } catch { t.skip('openssl unavailable'); return; }
  const seen = [];
  const server = http2.createSecureServer({ key: readFileSync(path.join(dir, 'k.pem')), cert: readFileSync(path.join(dir, 'c.pem')), allowHTTP1: false });
  server.on('stream', (stream, headers) => {
    seen.push(headers);
    if (headers[':path'].startsWith('/teapot')) { stream.respond({ ':status': 418 }); stream.end(); return; }
    const name = DNS.parseQueryName(Uint8Array.from(Buffer.from(new URL(`https://x${headers[':path']}`).searchParams.get('dns'), 'base64url')));
    stream.respond({ ':status': 200, 'content-type': 'application/dns-message' });
    stream.end(Buffer.from(DNS.buildResponse(name, { addresses: ['192.0.2.77'] })));
  });
  await new Promise((r) => server.listen(0, r));
  const base = `https://localhost:${server.address().port}`;
  const f = createH2Fetch({ headers: { 'user-agent': 'test' }, connectOptions: { ca: readFileSync(path.join(dir, 'c.pem')) } });
  try {
    const [a, b] = await Promise.all([DNS.resolve(`${base}/dns-query`, 'cira.ca', { fetchImpl: f }), DNS.resolve(`${base}/dns-query`, 'quad9.net', { fetchImpl: f })]);
    assert.deepEqual(a.addresses, ['192.0.2.77']);
    assert.deepEqual(b.addresses, ['192.0.2.77']);
    assert.equal(seen[0].accept, 'application/dns-message');
    assert.equal(seen[0]['user-agent'], 'test');
    await assert.rejects(DNS.resolve(`${base}/teapot`, 'cira.ca', { fetchImpl: f }), /HTTP 418/);
  } finally {
    f.close();
    await new Promise((r) => server.close(r));
  }
});
