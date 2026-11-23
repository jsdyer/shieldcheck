import * as M from './model.mjs';
import * as DNS from './dns.mjs';

const $ = (s) => document.querySelector(s);
function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'style') el.style.cssText = v;
    else el.setAttribute(k, v);
  }
  el.append(...kids.flat().filter((x) => x !== null && x !== undefined && x !== false));
  return el;
}
const fmt = new Intl.NumberFormat('en-CA');
const pct = (x) => (x === null ? '—' : `${Math.round(x * 100)}%`);
const when = (iso) => new Date(iso).toLocaleString('en-CA', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZoneName: 'short' });
const SYMBOL = { blocked: '■', allowed: '·', offline: '–', error: '!' };
const cell = (v) => h('td', { class: `v ${v}`, title: v }, SYMBOL[v] || '?');

let config, index, capture;

async function getJson(path) {
  const r = await fetch(path, { cache: 'no-cache' });
  if (!r.ok) throw new Error(`${r.status} for ${path}`);
  return r.json();
}

function renderScore() {
  const s = capture.summary;
  const sec = s.filter((x) => x.level === 'security' && x.live);
  const best = sec.length ? sec.reduce((a, b) => ((b.rate ?? -1) > (a.rate ?? -1) ? b : a)) : null;
  const threats = capture.rows.filter((r) => !r.control);
  const live = threats.filter((r) => Object.values(r.v).some((v) => v === 'blocked' || v === 'allowed'));
  const missed = live.filter((r) => capture.resolvers.filter((x) => x.level === 'security').every((x) => r.v[x.id] !== 'blocked'));
  $('#score-lede').textContent = best
    ? `${fmt.format(threats.length)} fresh threat domains were checked; ${fmt.format(live.length)} still resolved. ${best.name} blocked the most (${pct(best.rate)}). ${fmt.format(missed.length)} were blocked by none of the security filters.`
    : 'No live threat domains in this capture.';
  const ops = [...new Set(s.map((x) => x.operator))];
  $('#scoreboard').replaceChildren(...ops.map((op) => h('div', { class: 'op' }, h('h3', {}, op), h('div', { class: 'bars' },
    ...s.filter((x) => x.operator === op).flatMap((x) => [
      h('span', { class: 'name', title: x.name }, x.name.includes('·') ? x.name.split('·').pop().trim() : x.name),
      h('div', { class: 'track', role: 'img', 'aria-label': `${x.name}: ${pct(x.rate)} blocked` }, h('div', { class: `fill ${x.level}`, style: `width:${Math.round((x.rate || 0) * 100)}%` })),
      h('span', { class: 'num' }, `${pct(x.rate)} · ${x.blocked}/${x.live}`,
        x.unique !== null ? ` · ${x.unique} unique` : '',
        x.errors ? h('span', { class: 'warn' }, ` · ${x.errors} failed`) : '',
        x.controlBlocks.length ? h('span', { class: 'warn', title: x.controlBlocks.join(', ') }, ` · ${x.controlBlocks.length} control blocked`) : ''),
    ])))));
}

function renderSpeed() {
  const bt = index.block_times || {};
  const rows = capture.resolvers.filter((r) => r.baseline && bt[r.id]);
  const anyNew = rows.some((r) => bt[r.id].blockedAtFirstCheck + bt[r.id].blockedLater + bt[r.id].notBlocked > 0);
  $('#speed-lede').textContent = anyNew
    ? `Domains that first appeared in a feed after tracking began (${when(index.tracking_since)}), across ${fmt.format(index.tracked_domains)} domains seen in the last ${config.history_days} days. Captures run every six hours, so "first check" means within about six hours of the feed listing it.`
    : `Tracking began ${when(index.tracking_since)}. Block times appear once domains that are new since then have been checked in later captures.`;
  $('#speed').replaceChildren(
    h('thead', {}, h('tr', {}, ...['Filter', 'Blocked at first check', 'Blocked later', 'Median hours to block', 'Not blocked yet'].map((t) => h('th', { scope: 'col' }, t)))),
    h('tbody', {}, ...rows.map((r) => { const b = bt[r.id]; return h('tr', {}, h('td', {}, r.name), h('td', {}, fmt.format(b.blockedAtFirstCheck)), h('td', {}, fmt.format(b.blockedLater)), h('td', {}, b.medianHours === null ? '—' : b.medianHours.toFixed(1)), h('td', {}, fmt.format(b.notBlocked))); })));
}

function renderDomains() {
  const filtered = capture.resolvers.filter((r) => r.baseline);
  const security = filtered.filter((r) => r.level === 'security');
  const mode = $('#filter').value, q = $('#search').value.trim().toLowerCase();
  const isLive = (r) => filtered.some((x) => ['blocked', 'allowed'].includes(r.v[x.id]));
  const nBlocked = (r) => security.filter((x) => r.v[x.id] === 'blocked').length;
  const rows = capture.rows.filter((r) => {
    if (q && !r.domain.includes(q)) return false;
    if (mode === 'controls') return r.control;
    if (r.control) return false;
    if (mode === 'missed') return isLive(r) && nBlocked(r) === 0;
    if (mode === 'unique') return nBlocked(r) === 1;
    if (mode === 'offline') return filtered.every((x) => r.v[x.id] === 'offline');
    return true;
  });
  $('#count').textContent = `${fmt.format(rows.length)} shown`;
  $('#domains').replaceChildren(
    h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Domain'), h('th', { scope: 'col' }, 'Feed'), ...filtered.map((r) => h('th', { scope: 'col', title: r.name }, r.short || r.name)))),
    h('tbody', {}, ...rows.slice(0, 500).map((r) => h('tr', {}, h('td', { class: 'dom', title: r.domain }, r.domain), h('td', {}, r.feed), ...filtered.map((x) => cell(r.v[x.id]))))));
}

async function show(id) {
  $('#capture-note').textContent = 'Loading…';
  try { capture = await getJson(`./data/captures/${encodeURIComponent(id)}.json`); } catch { $('#capture-note').textContent = `Couldn't load capture ${id}.`; return; }
  const feeds = Object.entries(capture.feeds).map(([k, v]) => `${k} ${v.status === 'ok' ? `(${v.domains})` : `unavailable: ${v.status}`}`).join(', ');
  $('#capture-note').textContent = `Checked ${when(capture.captured)} · feeds: ${feeds}`;
  renderScore(); renderSpeed(); renderDomains();
  try { const u = new URL(location.href); u.searchParams.set('capture', id); history.replaceState(null, '', u); } catch { /* ignore */ }
}

// ---- Live check -------------------------------------------------------------
async function liveCheck(text) {
  const { hosts, invalid, truncated } = M.parseList(text, config.live_max_domains);
  const status = $('#live-status');
  status.classList.toggle('error', !hosts.length);
  if (!hosts.length) { status.textContent = 'Enter at least one domain or URL.'; return; }
  status.textContent = `Asking ${config.resolvers.length} DNS services about ${hosts.length} name${hosts.length === 1 ? '' : 's'}…`;
  const rows = hosts.map((d) => ({ domain: d, answers: {} }));
  const jobs = rows.flatMap((row) => config.resolvers.map((r) => ({ row, r })));
  let i = 0;
  const unreachable = new Set();
  await Promise.all(Array.from({ length: 6 }, async () => {
    while (i < jobs.length) {
      const { row, r } = jobs[i++];
      let ans;
      try { ans = await DNS.resolve(r.url, row.domain, { timeout: config.timeout_ms }); }
      catch (e) { ans = { error: e.name === 'TimeoutError' ? 'timeout' : 'not reachable from this browser' }; unreachable.add(r.name); }
      row.answers[r.id] = M.summarizeAnswer(ans);
    }
  }));
  const resolvers = config.resolvers;
  const local = M.detectSinkholes(rows, resolvers, 2);
  const known = Object.fromEntries(resolvers.filter((r) => r.baseline).map((r) => [r.id, [...new Set([...(capture?.sinkholes?.[r.id] || []), ...(local[r.id] || [])])]]));
  M.classifyRows(rows, resolvers, known);
  const filtered = resolvers.filter((r) => r.baseline);
  $('#live').replaceChildren(
    h('thead', {}, h('tr', {}, h('th', { scope: 'col' }, 'Domain'), ...filtered.map((r) => h('th', { scope: 'col', title: r.name }, r.short || r.name)))),
    h('tbody', {}, ...rows.map((r) => h('tr', {}, h('td', { class: 'dom', title: r.domain }, r.domain), ...filtered.map((x) => cell(r.v[x.id]))))));
  status.textContent = [
    `Checked ${new Date().toLocaleTimeString('en-CA').replace(/\.$/, '')}.`,
    invalid.length ? (invalid.length === 1 ? 'Skipped 1 entry that isn’t a domain name.' : `Skipped ${invalid.length} entries that aren’t domain names.`) : '',
    truncated ? `Only the first ${config.live_max_domains} were checked.` : '',
    unreachable.size ? `Not reachable from your browser: ${[...unreachable].join(', ')}.` : '',
  ].filter(Boolean).join(' ');
}

$('#live-form').addEventListener('submit', (e) => { e.preventDefault(); liveCheck($('#live-input').value); });
$('#live-clear').addEventListener('click', () => { $('#live-input').value = ''; $('#live').replaceChildren(); $('#live-status').textContent = ''; });
$('#filter').addEventListener('change', () => capture && renderDomains());
$('#search').addEventListener('input', () => capture && renderDomains());

try {
  config = await getJson('./config.json');
  $('#live-max').textContent = config.live_max_domains;
  index = await getJson('./data/index.json');
  if (!index.captures?.length) throw new Error('no captures');
  const sel = $('#capture');
  sel.replaceChildren(...index.captures.map((c, n) => h('option', { value: c.id }, `${c.id.replace('T', ' ')}:00 UTC${n === 0 ? ' (latest)' : ''}`)));
  const wanted = new URL(location.href).searchParams.get('capture');
  sel.value = index.captures.some((c) => c.id === wanted) ? wanted : index.captures[0].id;
  sel.disabled = index.captures.length < 2;
  sel.addEventListener('change', () => show(sel.value));
  await show(sel.value);
} catch (e) {
  if (!config) $('#capture-note').textContent = 'Configuration failed to load.';
  else { $('#capture').replaceChildren(h('option', {}, 'None')); $('#capture-note').textContent = 'No capture has been published yet. The scheduled build collects one every six hours. You can still check your own list below.'; }
  console.error(e);
}
