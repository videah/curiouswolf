function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding)
        .replace(/\-/g, '+')
        .replace(/_/g, '/');

    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);

    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

function askPermission() {
    return new Promise(function (resolve, reject) {
        const permissionResult = Notification.requestPermission(function (result) {
            resolve(result);
        });

        if (permissionResult) {
            permissionResult.then(resolve, reject);
        }
    }).then(function (permissionResult) {
        if (permissionResult !== 'granted') {
            throw new Error("We weren't granted permission.");
        }
    });
}

function getServerKey() {
    return fetch("/notifications/info").then(function (response) {
        return response.json();
    }).then(function (data) {
        return data.public_key;
    });
}

function subscribeUserToPush(serverKey) {
    return navigator.serviceWorker
        .register('/service-worker.js')
        .then(function (registration) {
            const subscribeOptions = {
                userVisibleOnly: true,
                applicationServerKey: urlBase64ToUint8Array(serverKey,),
            };

            return registration.pushManager.subscribe(subscribeOptions);
        })
        .then(function (pushSubscription) {
            console.log(
                'Received PushSubscription: ',
                JSON.stringify(pushSubscription),
            );
            return pushSubscription;
        });
}

function sendSubscriptionToBackEnd(subscription) {
    return fetch('/notifications/subscribe', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(subscription),
    })
        .then(function (response) {
            if (!response.ok) {
                throw new Error('Bad status code from server.');
            }
        })
}

window.onload = function () {
    if (!("serviceWorker" in navigator)) {
        // Service Worker isn't supported on this browser.
        return;
    }

    if (!("PushManager" in window)) {
        // Push isn't supported on this browser.
        return;
    }

    // Show any notification related UI.
    const notificationSection = document.getElementById("notifications");
    notificationSection.classList.remove("hidden");

    const notificationToggle = document.getElementById("notification-toggle");
    notificationToggle.addEventListener("change", async function (event) {
        if (event.target.checked) {
            askPermission().then(async function () {
                const key = await getServerKey();
                console.log("Got server key: ", key);
                const subscription = await subscribeUserToPush(key);
                await sendSubscriptionToBackEnd(subscription);
                console.log("Successfully subscribed to push notifications.");
            });
        }
    });
}