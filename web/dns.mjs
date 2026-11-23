// Minimal DNS wire format (RFC 1035) with EDNS(0) and Extended DNS Errors (RFC 8914),
// for DNS-over-HTTPS (RFC 8484) GET requests. Shared by the browser and the capture script.

export const TYPE = { A: 1, AAAA: 28, CNAME: 5, OPT: 41 };
export const RCODE = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' };
export const EDE = { 15: 'Blocked', 16: 'Censored', 17: 'Filtered', 18: 'Prohibited' };

function encodeName(name) {
  const out = [];
  for (const label of name.replace(/\.$/, '').split('.')) {
    const bytes = new TextEncoder().encode(label);
    if (!bytes.length || bytes.length > 63) throw new Error(`Invalid DNS label in ${name}`);
    out.push(bytes.length, ...bytes);
  }
  out.push(0);
  return out;
}

/** A recursive query with an EDNS OPT record (so resolvers can return Extended DNS Errors). Message ID 0 per RFC 8484. */
export function buildQuery(name, type = TYPE.A) {
  const bytes = [0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1, ...encodeName(name), type >> 8, type & 255, 0, 1,
    0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]; // OPT: root name, type 41, UDP size 1232, no flags, no options
  return new Uint8Array(bytes);
}

export function base64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export const dohUrl = (endpoint, name, type = TYPE.A) => `${endpoint}?dns=${base64url(buildQuery(name, type))}`;

function readName(view, offset) {
  const labels = [];
  let jumped = false, next = offset, guard = 0;
  for (;;) {
    if (guard++ > 128) throw new Error('DNS name loop');
    const len = view.getUint8(offset);
    if ((len & 0xc0) === 0xc0) {
      if (!jumped) next = offset + 2;
      offset = ((len & 0x3f) << 8) | view.getUint8(offset + 1);
      jumped = true;
      continue;
    }
    if (len === 0) { if (!jumped) next = offset + 1; break; }
    labels.push(new TextDecoder().decode(new Uint8Array(view.buffer, view.byteOffset + offset + 1, len)));
    offset += len + 1;
  }
  return { name: labels.join('.').toLowerCase(), next };
}

/** RFC 5952 text form: lowercase hex, longest run of two or more zero groups shortened to "::". */
export function formatIpv6(groups) {
  let best = { start: -1, len: 0 };
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > best.len) best = { start: i, len: j - i };
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (best.len < 2) return hex.join(':');
  return `${hex.slice(0, best.start).join(':')}::${hex.slice(best.start + best.len).join(':')}`;
}
const ipv6 = (view, o) => formatIpv6(Array.from({ length: 8 }, (_, i) => view.getUint16(o + i * 2)));

/** The question name in a query message (used to answer queries offline). */
export function parseQueryName(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return readName(view, 12).name;
}

/** Parse a DNS response into { rcode, addresses, cnames, ede: [{code, text}] }. */
export function parseResponse(buffer) {
  const view = new DataView(buffer instanceof ArrayBuffer ? buffer : buffer.buffer, buffer.byteOffset || 0, buffer.byteLength);
  if (view.byteLength < 12) throw new Error('DNS response too short');
  const flags = view.getUint16(2);
  let rcode = flags & 0x0f;
  const counts = [view.getUint16(4), view.getUint16(6), view.getUint16(8), view.getUint16(10)];
  let o = 12;
  for (let i = 0; i < counts[0]; i++) o = readName(view, o).next + 4;
  const addresses = [], cnames = [], ede = [];
  const total = counts[1] + counts[2] + counts[3];
  for (let i = 0; i < total; i++) {
    o = readName(view, o).next;
    const type = view.getUint16(o), ttl = view.getUint32(o + 4), len = view.getUint16(o + 8);
    const rd = o + 10;
    const section = i < counts[1] ? 'answer' : i < counts[1] + counts[2] ? 'authority' : 'additional';
    if (section === 'answer' && type === TYPE.A && len === 4) addresses.push([0, 1, 2, 3].map((k) => view.getUint8(rd + k)).join('.'));
    else if (section === 'answer' && type === TYPE.AAAA && len === 16) addresses.push(ipv6(view, rd));
    else if (section === 'answer' && type === TYPE.CNAME) cnames.push(readName(view, rd).name);
    else if (type === TYPE.OPT) {
      rcode |= (ttl >>> 24) << 4; // extended RCODE
      let p = rd;
      while (p + 4 <= rd + len) {
        const code = view.getUint16(p), olen = view.getUint16(p + 2);
        if (code === 15 && olen >= 2) {
          const info = view.getUint16(p + 4);
          const text = olen > 2 ? new TextDecoder().decode(new Uint8Array(view.buffer, view.byteOffset + p + 6, olen - 2)) : '';
          ede.push({ code: info, text });
        }
        p += 4 + olen;
      }
    }
    o = rd + len;
  }
  return { rcode: RCODE[rcode] || `RCODE${rcode}`, addresses, cnames, ede };
}

/** Build a response (used by tests and offline fixtures). answer: { rcode, addresses, ede:[{code,text}] } */
export function buildResponse(name, { rcode = 0, addresses = [], ede = [] } = {}) {
  const q = encodeName(name);
  const rr = [];
  for (const ip of addresses) {
    if (ip.includes(':')) {
      const parts = ip.split('::');
      const head = parts[0] ? parts[0].split(':') : [], tail = parts[1] ? parts[1].split(':') : [];
      const full = [...head, ...Array(8 - head.length - tail.length).fill('0'), ...tail].map((x) => parseInt(x || '0', 16));
      rr.push(0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16, ...full.flatMap((x) => [x >> 8, x & 255]));
    } else rr.push(0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, ...ip.split('.').map(Number));
  }
  const opts = ede.flatMap(({ code, text = '' }) => { const t = [...new TextEncoder().encode(text)]; return [0, 15, (t.length + 2) >> 8, (t.length + 2) & 255, code >> 8, code & 255, ...t]; });
  const opt = [0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, opts.length >> 8, opts.length & 255, ...opts];
  const header = [0, 0, 0x81, 0x80 | (rcode & 15), 0, 1, 0, addresses.length, 0, 0, 0, 1];
  return new Uint8Array([...header, ...q, 0, 1, 0, 1, ...rr, ...opt]).buffer;
}

/** Query one DoH endpoint over GET. Rejects on network/CORS/HTTP failure. */
export async function resolve(endpoint, name, { timeout = 8000, signal, fetchImpl = fetch } = {}) {
  const sig = signal ? AbortSignal.any([AbortSignal.timeout(timeout), signal]) : AbortSignal.timeout(timeout);
  const res = await fetchImpl(dohUrl(endpoint, name), { headers: { Accept: 'application/dns-message' }, signal: sig, credentials: 'omit', referrerPolicy: 'no-referrer' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return parseResponse(await res.arrayBuffer());
}
