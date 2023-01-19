window.onload = function() {
    const { startAuthentication } = SimpleWebAuthnBrowser;

    async function attemptRegistration() {
        const username = document.getElementById("username");

        const resp = await fetch("/auth/authenticate_start/" + username.value, { method: "POST" });

        let asseResp;
        try {
            const decoded = await resp.json()
            asseResp = await startAuthentication(decoded["publicKey"]);
        } catch (e) {
            console.log(e);
        }

        const url = "/auth/authenticate_finish";
        const verificationResp = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(asseResp),
        });

        if (verificationResp.status === 200) {
            document.location.href = "/";
        } else {
            alert("Failure!");
        }
    }

    const button = document.getElementById("login-button");
    button.addEventListener("click", attemptRegistration);
}