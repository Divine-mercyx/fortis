/*
 * Fortis service worker. It does one job: when a page cannot be loaded, show a Fortis screen
 * instead of the browser's error page.
 *
 *   - no connection on this device        -> offline.html
 *   - online, but the server is not there -> unavailable.html (also for 502, 503 and 504)
 *
 * It saves only those two pages. Every other request goes straight to the network, so it can
 * never serve an out-of-date copy of the site.
 */
const CACHE = 'fortis-status-v1';
const PAGES = ['offline.html', 'unavailable.html'];
const DOWN = new Set([502, 503, 504]);

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then((cache) => cache.addAll(PAGES.map((page) => new Request(page, { cache: 'reload' }))))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith('fortis-status-') && k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

/** A saved status page, addressed relative to where this worker is served from. */
const saved = (page) => caches.match(new URL(page, self.registration.scope).href);

self.addEventListener('fetch', (event) => {
  // Page loads only. Scripts, images, API calls and form posts are left alone.
  if (event.request.mode !== 'navigate') return;

  event.respondWith(
    fetch(event.request)
      .then(async (response) => (DOWN.has(response.status) ? (await saved('unavailable.html')) || response : response))
      .catch(async () => (await saved(self.navigator.onLine === false ? 'offline.html' : 'unavailable.html')) || Response.error()),
  );
});
