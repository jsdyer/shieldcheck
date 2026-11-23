import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as M from '../web/model.mjs';

const config = JSON.parse(readFileSync(new URL('../web/config.json', import.meta.url), 'utf8'));
const R = (ips) => ({ s: 'R', ips });
const N = { s: 'N' }, E = { s: 'E' };

test('hosts from URLs and feeds: dedupe, skip IPs, comments and shared platforms', () => {
  assert.equal(M.hostOf('HTTPS://Login.Example.Test:8443/path?x'), 'login.example.test');
  for (const bad of ['192.0.2.1/x', '# comment', '', 'not a url !!', 'localhost']) assert.equal(M.hostOf(bad), null, bad);
  const feed = 'http://a.bad.test/1\nhttp://a.bad.test/2\nhttps://docs.google.com/forms/x\nhttp://b.bad.test\n192.0.2.4\nhttp://c.bad.test';
  assert.deepEqual(M.parseFeed(feed, { skip: config.skip_suffixes }), { hosts: ['a.bad.test', 'b.bad.test', 'c.bad.test'], skipped: 1 });
  assert.deepEqual(M.parseFeed(feed, { max: 2, skip: config.skip_suffixes }).hosts, ['a.bad.test', 'b.bad.test']);
});

test('visitor list: lines or commas, invalid entries reported, capped', () => {
  const r = M.parseList('one.test, two.test\nhttps://three.test/login\nbad entry!!\none.test', 2);
  assert.deepEqual(r.hosts, ['one.test', 'two.test']);
  assert.deepEqual(r.invalid, ['bad entry!!']);
  assert.equal(r.truncated, 1);
});

test('verdicts against the unfiltered sibling', () => {
  assert.equal(M.verdict(R(['198.51.100.1']), R(['198.51.100.1'])), 'allowed');
  assert.equal(M.verdict(N, R(['198.51.100.1'])), 'blocked');                       // NXDOMAIN (Quad9 style)
  assert.equal(M.verdict(R(['0.0.0.0']), R(['198.51.100.1'])), 'blocked');          // null answer (Cloudflare style)
  assert.equal(M.verdict(R(['203.0.113.80']), R(['198.51.100.1']), ['203.0.113.80']), 'blocked'); // block page (CIRA style)
  assert.equal(M.verdict(R(['203.0.113.80']), R(['198.51.100.1'])), 'allowed');     // unknown different IP isn't assumed a block
  assert.equal(M.verdict({ s: 'R', ips: ['198.51.100.1'], ede: [15] }, R(['198.51.100.1'])), 'blocked');
  assert.equal(M.verdict(N, N), 'offline');
  assert.equal(M.verdict({ s: 'N', ede: [17] }, N), 'blocked');
  assert.equal(M.verdict(E, R(['1.1.1.1'])), 'error');
  assert.equal(M.verdict(R(['1.1.1.1']), E), 'error');
});

test('sinkholes need several distinct domains and must differ from the baseline answer', () => {
  const resolvers = [{ id: 'base', role: 'baseline' }, { id: 'f', baseline: 'base' }];
  const rows = ['a', 'b', 'c', 'd'].map((d, i) => ({ domain: `${d}.test`, answers: { base: R([`198.51.100.${i}`, '192.0.2.200']), f: R(i < 3 ? ['203.0.113.80'] : ['192.0.2.200']) } }));
  assert.deepEqual(M.detectSinkholes(rows, resolvers, 3), { f: ['203.0.113.80'] });
  assert.deepEqual(M.detectSinkholes(rows, resolvers, 4), { f: [] });
});

function sample() {
  const resolvers = [
    { id: 'b1', role: 'baseline', operator: 'One' }, { id: 's1', baseline: 'b1', level: 'security', name: 'One secure', operator: 'One' },
    { id: 'b2', role: 'baseline', operator: 'Two' }, { id: 's2', baseline: 'b2', level: 'security', name: 'Two secure', operator: 'Two' },
    { id: 'f2', baseline: 'b2', level: 'family', name: 'Two family', operator: 'Two' },
  ];
  const ok = R(['198.51.100.1']);
  const rows = [
    { domain: 'x.test', answers: { b1: ok, s1: N, b2: ok, s2: N, f2: N } },
    { domain: 'y.test', answers: { b1: ok, s1: N, b2: ok, s2: ok, f2: N } },
    { domain: 'z.test', answers: { b1: ok, s1: ok, b2: ok, s2: ok, f2: ok } },
    { domain: 'dead.test', answers: { b1: N, s1: N, b2: N, s2: N, f2: N } },
    { domain: 'ctrl.test', control: true, answers: { b1: ok, s1: ok, b2: ok, s2: ok, f2: N } },
  ];
  return { resolvers, rows: M.classifyRows(rows, resolvers, {}) };
}

test('summary: rates exclude dead domains, unique catches, control false positives', () => {
  const { resolvers, rows } = sample();
  const s = Object.fromEntries(M.summarize(rows, resolvers).map((x) => [x.id, x]));
  assert.equal(s.s1.live, 3); assert.equal(s.s1.blocked, 2); assert.equal(s.s1.unique, 1);
  assert.equal(s.s2.blocked, 1); assert.equal(s.s2.unique, 0);
  assert.equal(s.f2.unique, null);
  assert.deepEqual(s.f2.controlBlocks, ['ctrl.test']);
  assert.ok(Math.abs(s.s1.rate - 2 / 3) < 1e-9);
});

test('history records first block per resolver and block times count only new domains', () => {
  const { resolvers, rows } = sample();
  const t0 = '2026-11-23T00:00:00.000Z', t1 = '2026-11-23T06:00:00.000Z', t2 = '2026-11-23T12:00:00.000Z';
  let hist = M.updateHistory({}, rows, t0, 45);
  assert.equal(hist['x.test'].first_blocked.s1, t0);
  assert.equal(hist['ctrl.test'], undefined);
  // A new domain appears at t1, allowed everywhere; blocked by s2 at t2.
  const fresh = (v) => M.classifyRows([{ domain: 'new.test', answers: { b1: R(['1.2.3.4']), s1: R(['1.2.3.4']), b2: R(['1.2.3.4']), s2: v, f2: v } }], resolvers, {});
  hist = M.updateHistory(hist, fresh(R(['1.2.3.4'])), t1, 45);
  hist = M.updateHistory(hist, fresh(N), t2, 45);
  const bt = M.blockTimes(hist, ['s1', 's2'], t0);
  assert.deepEqual(bt.s2, { blockedAtFirstCheck: 0, blockedLater: 1, medianHours: 6, notBlocked: 0 });
  assert.deepEqual(bt.s1, { blockedAtFirstCheck: 0, blockedLater: 0, medianHours: null, notBlocked: 1 });
  // Pruning after history_days.
  assert.equal(Object.keys(M.updateHistory(hist, [], '2027-03-01T00:00:00.000Z', 45)).length, 0);
});

test('validation: too few live domains or every baseline down rejects the capture', () => {
  const { resolvers, rows } = sample();
  const c = { captured: '2026-11-23T00:00:00Z', resolvers, rows };
  assert.deepEqual(M.validateCapture(c, 3), []);
  assert.match(M.validateCapture(c, 10).join(), /only 3 feed domains/);
  const down = { ...c, rows: rows.map((r) => ({ ...r, answers: { ...r.answers, b1: E, b2: E } })) };
  assert.match(M.validateCapture(down, 0).join(), /every unfiltered resolver failed/);
  const oneDown = { ...c, rows: rows.map((r) => ({ ...r, answers: { ...r.answers, b1: E } })) };
  assert.deepEqual(M.validateCapture(oneDown, 1), []);
});

test('config: every filtered resolver has a baseline; an added resolver works without code changes', () => {
  const ids = new Set(config.resolvers.map((r) => r.id));
  for (const r of config.resolvers) {
    assert.match(r.url, /^https:\/\/.+\/dns-query$/);
    if (r.baseline) assert.ok(ids.has(r.baseline), r.id);
  }
  const extra = [...config.resolvers, { id: 'adguard', name: 'AdGuard', short: 'AdGuard', operator: 'AdGuard', url: 'https://dns.adguard-dns.com/dns-query', baseline: 'cloudflare', level: 'security' }];
  const rows = M.classifyRows([{ domain: 'q.test', answers: Object.fromEntries(extra.map((r) => [r.id, r.id === 'adguard' ? N : R(['198.51.100.3'])])) }], extra, {});
  const s = M.summarize(rows, extra);
  assert.equal(s.length, extra.filter((r) => r.baseline).length);
  assert.equal(s.find((x) => x.id === 'adguard').blocked, 1);
  assert.ok(config.feeds.every((f) => f.max_domains > 0));
});
