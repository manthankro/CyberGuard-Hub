
const CACHE = 'cyberguard-v13';
const ASSETS = [
  '/',
  '/static/style.css?v=20261019-v13',
  '/static/app.js',
  '/static/logo.jpg',
  '/static/manifest.json'
];
self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim())
  );
});
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET') return;
  if (url.pathname.startsWith('/api/')) return;
  event.respondWith(
    caches.match(event.request).then((cached) => cached || fetch(event.request).then((res) => {
      const copy = res.clone();
      if (res.ok && (url.origin === self.location.origin)) {
        caches.open(CACHE).then((c) => c.put(event.request, copy));
      }
      return res;
    }).catch(() => cached))
  );
});
