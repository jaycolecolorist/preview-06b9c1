/* Private preview: decrypts this site on this device once the passphrase is entered. Holds no secrets. */
const BASE = "/preview-06b9c1/";
const OPEN = new Set(['', 'index.html', '404.html', 'lock.html', 'sw.js', 'robots.txt']);
const TYPES = { html: 'text/html; charset=utf-8', js: 'application/javascript; charset=utf-8', css: 'text/css', json: 'application/json',
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp', svg: 'image/svg+xml', ico: 'image/x-icon',
  mp4: 'video/mp4', ttf: 'font/ttf', otf: 'font/otf', woff: 'font/woff', woff2: 'font/woff2', txt: 'text/plain' };
let keysP = null;
const films = new Map(); // decrypted films kept while the app is open, so seeking does not decrypt again
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
function idb() { return new Promise((res, rej) => { const r = indexedDB.open('pv', 1); r.onupgradeneeded = () => r.result.createObjectStore('k'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); }); }
async function rawKey() { const db = await idb(); return new Promise((res) => { const q = db.transaction('k').objectStore('k').get('key'); q.onsuccess = () => res(q.result || null); q.onerror = () => res(null); }); }
async function keys() {
  if (!keysP) keysP = rawKey().then(async (raw) => raw && {
    aes: await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']),
    mac: await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']),
  });
  const k = await keysP; if (!k) keysP = null; return k;
}
// After the first visit the device keeps the files that do not change under the same name (code, fonts,
// pictures, films; still encrypted), so the house opens quickly; pages and their data are always asked afresh.
const CACHE = 'pv-1';
const changing = (rel) => /\.(html|txt|json)$/.test(rel) || !rel.includes('.');
async function blob(rel, k, fresh) {
  const name = hex(await crypto.subtle.sign('HMAC', k.mac, new TextEncoder().encode(rel))).slice(0, 32);
  const url = BASE + 'd/' + name + '.bin';
  const keep = !fresh && !changing(rel) ? await caches.open(CACHE).catch(() => null) : null;
  const hit = keep ? await keep.match(url) : null;
  const r = hit || (await fetch(url, keep ? {} : { cache: 'no-cache' }));
  if (!r.ok) return null;
  if (keep && !hit) keep.put(url, r.clone()).catch(() => {});
  const b = new Uint8Array(await r.arrayBuffer());
  try {
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.slice(0, 12) }, k.aes, b.slice(12)));
    // Gzipped at lock time (code, styles, pages): unzip here; nothing else in the build starts with these two bytes.
    if (plain[0] === 0x1f && plain[1] === 0x8b) return await new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();
    return plain.buffer;
  } catch (e) {
    if (hit) { await keep.delete(url); return blob(rel, k, true); } // kept under an older passphrase
    throw e;
  }
}
function respond(req, rel, buf) {
  const ext = rel.split('.').pop().toLowerCase();
  const type = TYPES[ext] || 'application/octet-stream';
  const size = buf.byteLength;
  const m = /bytes=(\d*)-(\d*)/.exec(req.headers.get('range') || '');
  if (m && (m[1] || m[2])) {
    const start = m[1] ? +m[1] : Math.max(0, size - +m[2]);
    const end = m[1] && m[2] ? Math.min(+m[2], size - 1) : size - 1;
    if (start >= size) return new Response('', { status: 416, headers: { 'content-range': 'bytes */' + size } });
    return new Response(buf.slice(start, end + 1), { status: 206, headers: { 'content-type': type, 'content-range': 'bytes ' + start + '-' + end + '/' + size, 'accept-ranges': 'bytes', 'content-length': String(end - start + 1) } });
  }
  return new Response(buf, { headers: { 'content-type': type, 'accept-ranges': 'bytes', 'content-length': String(size) } });
}
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('message', (e) => { if (e.data === 'key-updated') keysP = null; });
// The website (under w/) is a set of pages; the app is one page that routes itself.
async function page(rel, k) {
  if (rel !== 'w' && !rel.startsWith('w/')) return blob('index.html', k, true);
  const r = rel.replace(/\/$/, '');
  for (const c of [r + '/index.html', r + '.html', r]) { const b = await blob(c, k, true).catch(() => null); if (b) return b; }
  return blob('w/404.html', k, true);
}
self.addEventListener('fetch', (e) => {
  const u = new URL(e.request.url);
  if (u.origin !== location.origin || e.request.method !== 'GET') return;
  // The website asks for some of its files from the root (/art/…, /brand/…): they are its own, under w/; and
  // /media/… are the photographs it shares with the app.
  const inside = u.pathname.startsWith(BASE);
  const rel = inside ? decodeURIComponent(u.pathname.slice(BASE.length)) : (u.pathname.startsWith('/media/') ? '' : 'w') + decodeURIComponent(u.pathname).replace(/^\/media\//, 'media/');
  if (e.request.mode === 'navigate') {
    if (!inside) return;
    e.respondWith((async () => {
      const k = await keys().catch(() => null);
      const html = k && (await page(rel, k).catch(() => null));
      return html ? new Response(html, { headers: { 'content-type': TYPES.html } }) : fetch(BASE + 'lock.html', { cache: 'no-cache' });
    })());
    return;
  }
  if (inside && (OPEN.has(rel) || rel.startsWith('d/'))) return;
  e.respondWith((async () => {
    const k = await keys();
    if (!k) return new Response('', { status: 403 });
    let buf = films.get(rel);
    if (!buf) {
      buf = await blob(rel, k);
      if (!buf) return new Response('', { status: 404 });
      if (rel.endsWith('.mp4')) { films.set(rel, buf); if (films.size > 3) films.delete(films.keys().next().value); }
    }
    return respond(e.request, rel, buf);
  })());
});
