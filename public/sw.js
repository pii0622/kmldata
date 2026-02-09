// Service Worker for map tile caching
const CACHE_NAME = 'map-tiles-v1';
const TILE_CACHE_NAME = 'gsi-tiles-v1';

// Cache expiration time (7 days for tiles)
const TILE_MAX_AGE = 7 * 24 * 60 * 60 * 1000;

// Install event
self.addEventListener('install', (event) => {
  self.skipWaiting();
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME && cacheName !== TILE_CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// Fetch event - cache map tiles
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Cache GSI map tiles
  if (url.hostname === 'cyberjapandata.gsi.go.jp') {
    event.respondWith(
      caches.open(TILE_CACHE_NAME).then((cache) => {
        return cache.match(event.request).then((cachedResponse) => {
          if (cachedResponse) {
            // Check if cache is still valid
            const cachedDate = cachedResponse.headers.get('sw-cached-date');
            if (cachedDate && (Date.now() - parseInt(cachedDate)) < TILE_MAX_AGE) {
              return cachedResponse;
            }
          }

          // Fetch from network and cache
          return fetch(event.request).then((networkResponse) => {
            if (networkResponse.ok) {
              // Clone the response and add cache date header
              const responseToCache = networkResponse.clone();
              const headers = new Headers(responseToCache.headers);
              headers.set('sw-cached-date', Date.now().toString());

              responseToCache.blob().then((blob) => {
                const cachedResponse = new Response(blob, {
                  status: responseToCache.status,
                  statusText: responseToCache.statusText,
                  headers: headers
                });
                cache.put(event.request, cachedResponse);
              });
            }
            return networkResponse;
          }).catch(() => {
            // Return cached response if network fails
            if (cachedResponse) {
              return cachedResponse;
            }
            // Return empty tile placeholder
            return new Response('', { status: 404 });
          });
        });
      })
    );
    return;
  }

  // For other requests, use network first
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});

// Message handler for cache management
self.addEventListener('message', (event) => {
  if (event.data.action === 'clearTileCache') {
    caches.delete(TILE_CACHE_NAME).then(() => {
      event.ports[0].postMessage({ success: true });
    });
  }

  if (event.data.action === 'getCacheSize') {
    caches.open(TILE_CACHE_NAME).then((cache) => {
      cache.keys().then((keys) => {
        event.ports[0].postMessage({ count: keys.length });
      });
    });
  }
});
