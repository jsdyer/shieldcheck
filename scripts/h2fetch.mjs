// Minimal fetch-like GET over HTTP/2 for DNS-over-HTTPS from Node.
// Node's built-in fetch speaks HTTP/1.1, which some DoH services (CIRA, Quad9) refuse with HTTP 505.
import http2 from 'node:http2';

export function createH2Fetch({ headers: extra = {}, connectOptions = {} } = {}) {
  const sessions = new Map();
  const session = (origin) => {
    let s = sessions.get(origin);
    if (!s || s.closed || s.destroyed) {
      s = http2.connect(origin, connectOptions);
      s.on('error', () => sessions.delete(origin));
      s.setTimeout(60000, () => s.close());
      sessions.set(origin, s);
    }
    return s;
  };
  function h2fetch(url, { headers = {}, signal } = {}) {
    const u = new URL(url);
    return new Promise((resolve, reject) => {
      if (signal?.aborted) { reject(signal.reason); return; }
      let req;
      try { req = session(u.origin).request({ ':method': 'GET', ':path': u.pathname + u.search, ...extra, accept: headers.Accept || '*/*' }); }
      catch (e) { reject(e); return; }
      const chunks = [];
      let status = 0;
      const abort = () => { req.close(http2.constants.NGHTTP2_CANCEL); reject(signal.reason || new Error('aborted')); };
      signal?.addEventListener('abort', abort, { once: true });
      req.on('response', (h) => { status = h[':status']; });
      req.on('data', (c) => chunks.push(c));
      req.on('error', (e) => { signal?.removeEventListener('abort', abort); reject(e); });
      req.on('end', () => {
        signal?.removeEventListener('abort', abort);
        const buf = Buffer.concat(chunks);
        resolve({ ok: status >= 200 && status < 300, status, arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) });
      });
      req.end();
    });
  }
  h2fetch.close = () => { for (const s of sessions.values()) s.close(); sessions.clear(); };
  return h2fetch;
}
