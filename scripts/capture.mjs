#!/usr/bin/env node
// Take one Shield Check capture: read the threat feeds, resolve every domain (plus the
// control list) through each filtering resolver and its unfiltered sibling, classify,
// and publish into web/data/ alongside earlier captures kept in .cache/.
//
//   node scripts/capture.mjs                                  # live
//   node scripts/capture.mjs --fixtures tests/fixtures/sim --now 2026-11-23T18:00:00Z
//
// Exits non-zero when validation fails, so the previous deployment stays live.

import { mkdir, readFile, writeFile, readdir, rm, copyFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as M from '../web/model.mjs';
import * as DNS from '../web/dns.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const opt = (n) => (args.includes(n) ? args[args.indexOf(n) + 1] : null);
const fixtures = opt('--fixtures') ? path.resolve(opt('--fixtures')) : null;
const CACHE = path.resolve(opt('--cache') || path.join(ROOT, '.cache', 'shieldcheck'));
const OUT = path.resolve(opt('--out') || path.join(ROOT, 'web', 'data'));
const now = opt('--now') ? new Date(opt('--now')) : new Date();
const config = JSON.parse(await readFile(path.join(ROOT, 'web', 'config.json'), 'utf8'));
const UA = { 'User-Agent': 'coolcode.ca/shieldcheck (github.com/jsdyer/shieldcheck)' };

// Offline mode: feeds come from <fixtures>/<feed id>.txt and resolver answers from <fixtures>/answers.json.
const sim = fixtures ? JSON.parse(await readFile(path.join(fixtures, 'answers.json'), 'utf8')) : null;
const simFetch = async (url) => {
  const u = new URL(url);
  const resolver = config.resolvers.find((r) => url.startsWith(r.url));
  const q = DNS.parseQueryName(Uint8Array.from(atob(u.searchParams.get('dns').replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)));
  const a = sim[resolver.id]?.[q] ?? sim.default?.[q];
  if (a === 'error') return { ok: false, status: 502 };
  return { ok: true, arrayBuffer: async () => DNS.buildResponse(q, a || { rcode: 3 }) };
};

async function feedText(feed) {
  if (fixtures) return readFile(path.join(fixtures, `${feed.id}.txt`), 'utf8');
  const res = await fetch(feed.url, { headers: UA, signal: AbortSignal.timeout(30000) });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.text();
}

// 1. Feeds → domains
const feeds = {};
const rows = [];
const seen = new Set();
for (const feed of config.feeds) {
  try {
    const { hosts, skipped } = M.parseFeed(await feedText(feed), { max: feed.max_domains, skip: config.skip_suffixes });
    const fresh = hosts.filter((h) => !seen.has(h));
    fresh.forEach((h) => { seen.add(h); rows.push({ domain: h, feed: feed.id, answers: {} }); });
    feeds[feed.id] = { status: 'ok', domains: fresh.length, skipped_shared: skipped };
    console.log(`✓ feed ${feed.id}: ${fresh.length} domains (${skipped} on shared platforms skipped)`);
  } catch (e) {
    feeds[feed.id] = { status: String(e.message).slice(0, 160), domains: 0 };
    console.error(`✗ feed ${feed.id}: ${e.message}`);
  }
}
for (const c of config.controls) {
  const h = M.hostOf(c);
  if (h && !seen.has(h)) { seen.add(h); rows.push({ domain: h, feed: 'control', control: true, answers: {} }); }
}

// 2. Resolve every domain on every resolver, with bounded concurrency.
const jobs = rows.flatMap((row) => config.resolvers.map((r) => ({ row, r })));
let next = 0;
async function worker() {
  while (next < jobs.length) {
    const { row, r } = jobs[next++];
    let ans;
    try { ans = await DNS.resolve(r.url, row.domain, { timeout: config.timeout_ms, fetchImpl: fixtures ? simFetch : (u, o) => fetch(u, { ...o, headers: { ...o.headers, ...UA } }) }); }
    catch (e) { ans = { error: e.name === 'TimeoutError' ? 'timeout' : e.message }; }
    row.answers[r.id] = M.summarizeAnswer(ans);
  }
}
await Promise.all(Array.from({ length: config.concurrency }, worker));

// 3. Classify and summarise.
const resolvers = config.resolvers.map(({ id, name, short, operator, role, baseline, level }) => ({ id, name, short, operator, role, baseline, level }));
const sinkholes = M.detectSinkholes(rows, resolvers, config.sinkhole_min_domains);
M.classifyRows(rows, resolvers, sinkholes);
const capture = {
  captured: now.toISOString(), id: M.slotId(now.toISOString()), resolvers, feeds, sinkholes,
  summary: M.summarize(rows, resolvers), rows,
};
const problems = M.validateCapture(capture, config.min_live_domains);
if (problems.length) {
  console.error(`Capture rejected, keeping the last good deployment:\n- ${problems.join('\n- ')}`);
  process.exit(1);
}
for (const s of capture.summary) console.log(`  ${s.id}: blocked ${s.blocked}/${s.live}${s.errors ? `, ${s.errors} errors` : ''}${s.controlBlocks.length ? `, controls blocked: ${s.controlBlocks.join(' ')}` : ''}`);

// 4. History (first seen / first blocked) and retention.
await mkdir(path.join(CACHE, 'captures'), { recursive: true });
let history = {}, index = [], tracking = capture.captured;
try { history = JSON.parse(await readFile(path.join(CACHE, 'history.json'), 'utf8')); } catch { /* first run */ }
try { index = JSON.parse(await readFile(path.join(CACHE, 'index.json'), 'utf8')); } catch { /* first run */ }
try { tracking = JSON.parse(await readFile(path.join(CACHE, 'tracking.json'), 'utf8')).since; } catch { /* first run */ }
history = M.updateHistory(history, rows, capture.captured, config.history_days);
await writeFile(path.join(CACHE, 'captures', `${capture.id}.json`), JSON.stringify(capture));
const entry = {
  id: capture.id, captured: capture.captured,
  domains: rows.filter((r) => !r.control).length,
  feeds: Object.fromEntries(Object.entries(feeds).map(([k, v]) => [k, v.status])),
};
const { kept, dropped } = M.updateIndex(index, entry, config.keep_captures);
for (const d of dropped) await rm(path.join(CACHE, 'captures', `${d.id}.json`), { force: true });
await writeFile(path.join(CACHE, 'index.json'), JSON.stringify(kept));
await writeFile(path.join(CACHE, 'history.json'), JSON.stringify(history));
await writeFile(path.join(CACHE, 'tracking.json'), JSON.stringify({ since: tracking }));

// 5. Publish into web/data/.
await rm(OUT, { recursive: true, force: true });
await mkdir(path.join(OUT, 'captures'), { recursive: true });
const present = new Set(await readdir(path.join(CACHE, 'captures')));
const published = kept.filter((e) => present.has(`${e.id}.json`));
for (const e of published) await copyFile(path.join(CACHE, 'captures', `${e.id}.json`), path.join(OUT, 'captures', `${e.id}.json`));
const filteredIds = resolvers.filter((r) => r.baseline).map((r) => r.id);
await writeFile(path.join(OUT, 'index.json'), JSON.stringify({
  built: now.toISOString(), tracking_since: tracking, captures: published,
  block_times: M.blockTimes(history, filteredIds, tracking), tracked_domains: Object.keys(history).length,
}, null, 1));
console.log(`Published ${published.length} capture(s); newest ${capture.id}.`);
