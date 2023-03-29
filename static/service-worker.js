self.addEventListener('push', function(event) {
    if (!(self.Notification && self.Notification.permission === "granted")) {
        return;
    }

    const data = event.data.json();
    const title = data.title;
    const body = data.body;

    const promiseChain = self.registration.showNotification(
        title,
        {
            body: body,
        }
    );

    console.log("Waiting for promise chain to finish");
    event.waitUntil(promiseChain);
});

self.addEventListener('fetch', function(event) {
    event.respondWith(async function() {
        try {
            const res = await fetch(event.request);
            const cache = await caches.open('cache');
            await cache.put(event.request.url, res.clone());
            return res;
        } catch(error) {
            return caches.match(event.request);
        }
    }());
});