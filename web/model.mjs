// Pure logic for Shield Check: feed parsing, verdicts, sinkhole detection, summaries and
// block-time history. Shared by the browser and scripts/capture.mjs; unit-tested directly.

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const isIp = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':');

/** Hostname from a URL or bare name; null if it isn't a usable domain. */
export function hostOf(text) {
  let s = String(text || '').trim().toLowerCase();
  if (!s || s.startsWith('#')) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//.test(s)) s = `http://${s}`;
  let host;
  try { host = new URL(s).hostname.replace(/\.$/, ''); } catch { return null; }
  if (!host || isIp(host) || host.startsWith('[')) return null;
  const labels = host.split('.');
  return labels.length >= 2 && labels.every((l) => LABEL.test(l)) && host.length <= 253 ? host : null;
}

export const matchesSuffix = (host, suffixes) => suffixes.some((s) => host === s || host.endsWith(`.${s}`));

/** Distinct hostnames from a feed body (one URL or host per line), in feed order, skipping shared platforms. */
export function parseFeed(text, { max = Infinity, skip = [] } = {}) {
  const out = [];
  const seen = new Set();
  let skipped = 0;
  for (const line of String(text).split(/\r?\n/)) {
    if (line.trimStart().startsWith('#')) continue;
    // Plain lists hold one URL or host per line; CSV exports hold the URL in one quoted column.
    const url = line.match(/https?:\/\/[^\s",]+/i)?.[0];
    const host = hostOf(url || line);
    if (!host || seen.has(host)) continue;
    seen.add(host);
    if (matchesSuffix(host, skip)) { skipped++; continue; }
    out.push(host);
    if (out.length >= max) break;
  }
  return { hosts: out, skipped };
}

/** Visitor list for the live check: one per line or comma-separated. */
export function parseList(text, max) {
  const hosts = [], invalid = [];
  for (const raw of String(text).split(/[\n,]+/).map((x) => x.trim()).filter(Boolean)) {
    const h = hostOf(raw);
    if (h) { if (!hosts.includes(h)) hosts.push(h); } else invalid.push(raw);
  }
  return { hosts: hosts.slice(0, max), invalid, truncated: Math.max(0, hosts.length - max) };
}

const SPECIAL = [/^0\.0\.0\.0$/, /^::$/, /^127\./, /^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^146\.112\.61\.1\d\d$/];
export const isNullAnswer = (ip) => SPECIAL.some((r) => r.test(ip));
const BLOCK_EDE = new Set([15, 16, 17]);

/** Compact result for storage: R resolves / N nxdomain-or-empty / E error, plus addresses and EDE. */
export function summarizeAnswer(ans) {
  if (!ans || ans.error) return { s: 'E', err: ans?.error ? String(ans.error).slice(0, 80) : 'no answer' };
  const out = { s: ans.addresses.length ? 'R' : 'N', rc: ans.rcode };
  if (ans.addresses.length) out.ips = ans.addresses.slice(0, 4);
  if (ans.ede?.length) out.ede = ans.ede.map((e) => e.code);
  return out;
}

/**
 * Per filtered resolver, addresses it returned (instead of the baseline's) for at least `min`
 * different domains: those are block pages / sinkholes.
 */
export function detectSinkholes(rows, resolvers, min) {
  const out = {};
  for (const r of resolvers.filter((x) => x.baseline)) {
    const tally = new Map();
    for (const row of rows) {
      const f = row.answers[r.id], b = row.answers[r.baseline];
      if (f?.s !== 'R' || b?.s !== 'R') continue;
      for (const ip of f.ips || []) if (!(b.ips || []).includes(ip)) tally.set(ip, (tally.get(ip) || new Set()).add(row.domain));
    }
    out[r.id] = [...tally].filter(([, set]) => set.size >= min).map(([ip]) => ip).sort();
  }
  return out;
}

/**
 * Verdict for one filtered resolver vs its unfiltered sibling:
 *  blocked  – EDE Blocked/Censored/Filtered, or no/sinkhole answer while the baseline resolves
 *  allowed  – resolves like the baseline
 *  offline  – the baseline doesn't resolve it either (domain already dead)
 *  error    – a query failed
 */
export function verdict(filtered, baseline, sinkholes = []) {
  if (!filtered || filtered.s === 'E' || !baseline || baseline.s === 'E') return 'error';
  if ((filtered.ede || []).some((c) => BLOCK_EDE.has(c))) return 'blocked';
  if (baseline.s !== 'R') return 'offline';
  if (filtered.s !== 'R') return 'blocked';
  const ips = filtered.ips || [];
  if (ips.length && ips.every((ip) => isNullAnswer(ip) || sinkholes.includes(ip))) return 'blocked';
  return 'allowed';
}

export function classifyRows(rows, resolvers, sinkholes) {
  for (const row of rows) {
    row.v = {};
    for (const r of resolvers.filter((x) => x.baseline)) row.v[r.id] = verdict(row.answers[r.id], row.answers[r.baseline], sinkholes[r.id]);
  }
  return rows;
}

/** Per filtered resolver: how many live threat domains it blocked, unique catches, and control false positives. */
export function summarize(rows, resolvers) {
  const filtered = resolvers.filter((r) => r.baseline);
  const threats = rows.filter((r) => !r.control);
  const controls = rows.filter((r) => r.control);
  const security = filtered.filter((r) => r.level === 'security').map((r) => r.id);
  return filtered.map((r) => {
    const live = threats.filter((t) => ['blocked', 'allowed'].includes(t.v[r.id]));
    const blocked = live.filter((t) => t.v[r.id] === 'blocked');
    const unique = r.level === 'security'
      ? blocked.filter((t) => security.every((o) => o === r.id || t.v[o] !== 'blocked')).length
      : null;
    return {
      id: r.id, name: r.name, short: r.short || r.name, operator: r.operator, level: r.level,
      live: live.length, blocked: blocked.length, rate: live.length ? blocked.length / live.length : null,
      unique, errors: threats.filter((t) => t.v[r.id] === 'error').length,
      controlBlocks: controls.filter((c) => c.v[r.id] === 'blocked').map((c) => c.domain),
    };
  });
}

/** Update per-domain history: first/last seen and the first capture each resolver blocked it in. */
export function updateHistory(history, rows, capturedIso, keepDays) {
  const h = { ...(history || {}) };
  for (const row of rows.filter((r) => !r.control)) {
    const e = h[row.domain] ? { ...h[row.domain], first_blocked: { ...h[row.domain].first_blocked } } : { feed: row.feed, first_seen: capturedIso, first_blocked: {} };
    e.last_seen = capturedIso;
    for (const [id, v] of Object.entries(row.v)) if (v === 'blocked' && !e.first_blocked[id]) e.first_blocked[id] = capturedIso;
    h[row.domain] = e;
  }
  const cutoff = Date.parse(capturedIso) - keepDays * 864e5;
  for (const [d, e] of Object.entries(h)) if (Date.parse(e.last_seen) < cutoff) delete h[d];
  return h;
}

/**
 * Hours from a domain's first appearance to each resolver's first block, for domains first seen
 * after `since` (so domains already in the feed before tracking began don't count as instant).
 */
export function blockTimes(history, resolverIds, since) {
  const out = {};
  for (const id of resolverIds) {
    const hours = [];
    let never = 0;
    for (const e of Object.values(history)) {
      if (Date.parse(e.first_seen) <= Date.parse(since)) continue;
      if (e.first_blocked[id]) hours.push((Date.parse(e.first_blocked[id]) - Date.parse(e.first_seen)) / 3600e3);
      else never++;
    }
    hours.sort((a, b) => a - b);
    const median = hours.length ? (hours.length % 2 ? hours[(hours.length - 1) / 2] : (hours[hours.length / 2 - 1] + hours[hours.length / 2]) / 2) : null;
    out[id] = { blockedAtFirstCheck: hours.filter((x) => x === 0).length, blockedLater: hours.filter((x) => x > 0).length, medianHours: median, notBlocked: never };
  }
  return out;
}

/** Capture slot id: UTC date + hour, e.g. 2026-11-23T18. */
export const slotId = (iso) => new Date(iso).toISOString().slice(0, 13);

export function updateIndex(index, entry, keep) {
  const rest = (Array.isArray(index) ? index : []).filter((e) => e.id !== entry.id);
  const all = [entry, ...rest].sort((a, b) => b.id.localeCompare(a.id));
  return { kept: all.slice(0, keep), dropped: all.slice(keep) };
}

export function validateCapture(c, minLive) {
  const problems = [];
  if (!c?.captured || !Array.isArray(c.rows)) return ['malformed capture'];
  const baselines = c.resolvers.filter((r) => r.role === 'baseline').map((r) => r.id);
  const live = c.rows.filter((r) => !r.control && baselines.some((b) => r.answers[b]?.s === 'R')).length;
  if (live < minLive) problems.push(`only ${live} feed domains resolved on any baseline resolver (need ${minLive})`);
  const dead = baselines.filter((b) => c.rows.length && c.rows.every((r) => r.answers[b]?.s === 'E'));
  if (baselines.length && dead.length === baselines.length) problems.push('every unfiltered resolver failed every query');
  return problems;
}
