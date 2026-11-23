import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, cpSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SIM = path.join(ROOT, 'tests', 'fixtures', 'sim');
const run = (args) => spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'capture.mjs'), ...args], { encoding: 'utf8' });

test('captures accumulate, and a domain new since tracking began gets a block time', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'shield-'));
  const cache = path.join(dir, 'cache'), out = path.join(dir, 'out');
  const sim2 = path.join(dir, 'sim2'), sim3 = path.join(dir, 'sim3');
  cpSync(SIM, sim2, { recursive: true });
  // Capture 2: a new phishing domain appears, resolving everywhere.
  writeFileSync(path.join(sim2, 'openphish.txt'), `${readFileSync(path.join(SIM, 'openphish.txt'), 'utf8')}https://fresh-scam.example-phish.test/x\n`);
  const a2 = JSON.parse(readFileSync(path.join(SIM, 'answers.json'), 'utf8'));
  for (const r of Object.keys(a2)) a2[r]['fresh-scam.example-phish.test'] = { addresses: ['198.51.100.99'] };
  writeFileSync(path.join(sim2, 'answers.json'), JSON.stringify(a2));
  // Capture 3: Quad9 now blocks it.
  cpSync(sim2, sim3, { recursive: true });
  a2.quad9['fresh-scam.example-phish.test'] = { rcode: 3 };
  writeFileSync(path.join(sim3, 'answers.json'), JSON.stringify(a2));

  for (const [fx, now] of [[SIM, '2026-11-23T00:00:00Z'], [sim2, '2026-11-23T06:00:00Z'], [sim3, '2026-11-23T12:00:00Z'], [sim3, '2026-11-23T12:40:00Z']]) {
    const r = run(['--fixtures', fx, '--cache', cache, '--out', out, '--now', now]);
    assert.equal(r.status, 0, r.stderr);
  }
  const index = JSON.parse(readFileSync(path.join(out, 'index.json'), 'utf8'));
  assert.deepEqual(index.captures.map((c) => c.id), ['2026-11-23T12', '2026-11-23T06', '2026-11-23T00']);
  assert.equal(index.tracking_since, '2026-11-23T00:00:00.000Z');
  assert.deepEqual(index.block_times.quad9, { blockedAtFirstCheck: 0, blockedLater: 1, medianHours: 6, notBlocked: 0 });
  assert.equal(index.block_times['cira-protected'].notBlocked, 1);
  assert.equal(readdirSync(path.join(out, 'captures')).length, 3);
  const cap = JSON.parse(readFileSync(path.join(out, 'captures', '2026-11-23T12.json'), 'utf8'));
  assert.deepEqual(cap.sinkholes['cira-protected'], ['203.0.113.80']);
  assert.equal(cap.rows.find((r) => r.domain === 'cbc.ca').v['cira-family'], 'blocked');
  assert.ok(cap.rows.every((r) => !r.domain.endsWith('google.com')));
});

test('feeds that fail entirely leave nothing published and exit non-zero', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'shield-'));
  const fx = path.join(dir, 'sim');
  cpSync(SIM, fx, { recursive: true });
  writeFileSync(path.join(fx, 'openphish.txt'), '');
  writeFileSync(path.join(fx, 'urlhaus.txt'), '# nothing today\n');
  const out = path.join(dir, 'out');
  const r = run(['--fixtures', fx, '--cache', path.join(dir, 'cache'), '--out', out]);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /keeping the last good deployment/);
  assert.throws(() => readdirSync(out));
});

test('keyed feeds name their secret, and no key is stored in config.json', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'shield-'));
  const cfg = JSON.parse(readFileSync(path.join(ROOT, 'web', 'config.json'), 'utf8'));
  assert.equal(cfg.feeds.find((f) => f.id === 'urlhaus').secret, 'ABUSECH_AUTH_KEY');
  assert.ok(!JSON.stringify(cfg).match(/[0-9a-f]{40,}/), 'no keys in config');
});
