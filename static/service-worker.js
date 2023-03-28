self.addEventListener('push', function(event) {
    if (!(self.Notification && self.Notification.permission === "granted")) {
        return;
    }

    const title = "curiouswolf";
    const body = event.data.text() ?? "👻 Unknown Message Received";
    const options = {
        body: body
    };

    const promiseChain = self.registration.showNotification(title, options);

    console.log(options);
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