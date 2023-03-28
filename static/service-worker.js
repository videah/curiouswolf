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