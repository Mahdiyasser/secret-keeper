/* service-worker.js - Service Worker for Secret Keeper PWA */

const CACHE_NAME = 'secret-keeper';
// List of all files that make up the "App Shell" to be cached for offline use.
const ASSETS_TO_CACHE = [
    '/',
    '/index.html',
    '/style.css',
    '/script.js',
    // External CDN links for offline functionality
    'https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js',
    'https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap',
    // Your specific icons in the root directory
    '/favicon.ico',
    '/icon-192.png',
    '/icon-512.png'
];

// 1. Installation: Cache the assets
self.addEventListener('install', (event) => {
    // Perform install steps
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => {
                console.log('Service Worker: Caching App Shell Assets');
                // Adds all files in the list to the cache
                return cache.addAll(ASSETS_TO_CACHE);
            })
    );
});

// 2. Activation: Clean up old caches
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames.map((cacheName) => {
                    // Delete any caches that don't match the current CACHE_NAME
                    if (cacheName !== CACHE_NAME) {
                        console.log('Service Worker: Deleting old cache:', cacheName);
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
});

// 3. Fetch: Serve content from cache, falling back to network
self.addEventListener('fetch', (event) => {
    // For local requests (app shell files)
    if (event.request.url.startsWith(self.location.origin)) {
        event.respondWith(
            caches.match(event.request)
                .then((response) => {
                    // Cache hit - return response
                    if (response) {
                        return response;
                    }
                    // No cache - fetch from network
                    return fetch(event.request);
                })
        );
    }
    // For external requests (like CryptoJS CDN, Google Fonts)
    else {
        // Cache-first, then Network strategy for CDNs
        event.respondWith(
            caches.match(event.request).then((response) => {
                return response || fetch(event.request).then((response) => {
                    return caches.open(CACHE_NAME).then((cache) => {
                        // Cache a copy of the new response, but only if it's valid (status 200)
                        if (response.status === 200) {
                             cache.put(event.request, response.clone());
                        }
                        return response;
                    });
                });
            }).catch(() => {
                // Fail gracefully
            })
        );
    }
});
