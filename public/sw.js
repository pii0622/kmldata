// Service Worker for map tile caching and push notifications
const CACHE_NAME = 'map-tiles-v1';
const TILE_CACHE_NAME = 'gsi-tiles-v1';

// Cache expiration time (7 days for tiles)
const TILE_MAX_AGE = 7 * 24 * 60 * 60 * 1000;

// Install event - wait for user to reload (shows update badge)
self.addEventListener('install', (event) => {
  // Don't skipWaiting automatically - let the app show a reload badge first
  // skipWaiting will be triggered by a message from the page
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

// Push event - handle incoming push notifications
self.addEventListener('push', (event) => {
  let data = { title: 'Fieldnota', body: '新しい更新があります', type: 'general' };

  try {
    if (event.data) {
      data = event.data.json();
    }
  } catch (e) {
    console.error('Failed to parse push data:', e);
  }

  const options = {
    body: data.body,
    icon: '/icons/icon-192.svg',
    badge: '/icons/icon-192.svg',
    vibrate: [100, 50, 100],
    tag: data.type + '-' + (data.id || Date.now()),
    renotify: true,
    data: {
      type: data.type,
      id: data.id,
      url: data.url || '/'
    }
  };

  event.waitUntil(
    Promise.all([
      self.registration.showNotification(data.title, options),
      // Notify all open windows to refresh their notification count
      clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
        clientList.forEach(client => {
          client.postMessage({ type: 'push-received', data: data });
        });
      }),
      // Update app badge
      self.navigator?.setAppBadge?.().catch(() => {})
    ])
  );
});

// Notification click event
self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  const urlToOpen = event.notification.data?.url || '/';

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      // Check if there's already a window open
      for (const client of clientList) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          client.focus();
          client.postMessage({
            type: 'notification-click',
            data: event.notification.data
          });
          return;
        }
      }
      // If no window is open, open a new one
      if (clients.openWindow) {
        return clients.openWindow(urlToOpen);
      }
    })
  );
});

// Fetch event - cache map tiles
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Skip API requests - let them go directly to network
  if (url.pathname.startsWith('/api/')) {
    return;
  }

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

  if (event.data.action === 'skipWaiting') {
    self.skipWaiting();
  }
});
