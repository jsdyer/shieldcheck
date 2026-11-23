import test from 'node:test';
import assert from 'node:assert/strict';
import * as DNS from '../web/dns.mjs';

test('query: RD set, ID 0, one question, EDNS OPT, base64url without padding', () => {
  const q = DNS.buildQuery('Example.CA');
  assert.deepEqual([...q.slice(0, 12)], [0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1]);
  assert.equal(DNS.parseQueryName(q), 'example.ca');
  const url = DNS.dohUrl('https://dns.example/dns-query', 'cira.ca');
  assert.match(url, /^https:\/\/dns\.example\/dns-query\?dns=[A-Za-z0-9_-]+$/);
  assert.throws(() => DNS.buildQuery('bad..name'), /Invalid DNS label/);
});

test('response round trip: A, AAAA (RFC 5952), NXDOMAIN and Extended DNS Errors', () => {
  const ok = DNS.parseResponse(DNS.buildResponse('cira.ca', { addresses: ['192.0.2.1', '2001:db8::1', '2606:4700:0:0:0:0:6810:84e5'] }));
  assert.equal(ok.rcode, 'NOERROR');
  assert.deepEqual(ok.addresses, ['192.0.2.1', '2001:db8::1', '2606:4700::6810:84e5']);
  const blocked = DNS.parseResponse(DNS.buildResponse('bad.test', { addresses: ['0.0.0.0'], ede: [{ code: 17, text: 'Filtered' }] }));
  assert.deepEqual(blocked.ede, [{ code: 17, text: 'Filtered' }]);
  assert.equal(DNS.parseResponse(DNS.buildResponse('gone.test', { rcode: 3 })).rcode, 'NXDOMAIN');
  assert.equal(DNS.formatIpv6([0, 0, 0, 0, 0, 0, 0, 0]), '::');
  assert.equal(DNS.formatIpv6([0x2001, 0xdb8, 0, 1, 0, 0, 0, 1]), '2001:db8:0:1::1');
});

test('parses compressed CNAME chains and ignores non-answer sections', () => {
  // Hand-built: www.a.test CNAME a.test (pointer), a.test A 192.0.2.7, plus an OPT with extended rcode bits 0
  const name = [3, 119, 119, 119, 1, 97, 4, 116, 101, 115, 116, 0];
  const bytes = [0, 0, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 1, ...name, 0, 1, 0, 1,
    0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 16,
    0xc0, 16, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7,
    0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0];
  const r = DNS.parseResponse(new Uint8Array(bytes).buffer);
  assert.deepEqual(r.cnames, ['a.test']);
  assert.deepEqual(r.addresses, ['192.0.2.7']);
  assert.throws(() => DNS.parseResponse(new Uint8Array(4).buffer), /too short/);
});

test('resolve() uses GET with the dns-message Accept header and surfaces HTTP errors', async () => {
  let seen;
  const fake = async (url, opts) => { seen = { url, opts }; return { ok: true, arrayBuffer: async () => DNS.buildResponse('cira.ca', { addresses: ['192.0.2.9'] }) }; };
  const r = await DNS.resolve('https://dns.example/dns-query', 'cira.ca', { fetchImpl: fake });
  assert.deepEqual(r.addresses, ['192.0.2.9']);
  assert.equal(seen.opts.headers.Accept, 'application/dns-message');
  await assert.rejects(DNS.resolve('https://x/dns-query', 'cira.ca', { fetchImpl: async () => ({ ok: false, status: 403 }) }), /HTTP 403/);
});
