window.onload = function() {
    const { startRegistration } = SimpleWebAuthnBrowser;

    async function attemptRegistration() {
        const username = document.getElementById("username");

        const resp = await fetch("/auth/register_start/" + username.value, {method: "POST"});

        let attResp;
        try {
            const decoded = await resp.json()
            attResp = await startRegistration(decoded["publicKey"]);
        } catch (e) {
            console.log(e);
        }

        const url = "/auth/register_finish";
        const verificationResp = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(attResp),
        });

        console.log(verificationResp.body);

        if (verificationResp.status === 200) {
            alert("Success!");
        } else {
            alert("Failure!");
        }
    }

    const button = document.getElementById("register-button");
    button.addEventListener("click", attemptRegistration);
}