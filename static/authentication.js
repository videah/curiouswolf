window.onload = function() {
    const { startAuthentication } = SimpleWebAuthnBrowser;

    const button = document.getElementById("login-button");
    const error = document.getElementById("error-label");

    async function attemptRegistration() {
        button.classList.add("loading");

        const username = document.getElementById("username");

        if (username.value === "") {
            error.innerText = "Username cannot be empty";
            button.classList.remove("loading");
            return;
        }

        const resp = await fetch("/auth/authenticate_start/" + username.value, { method: "POST" });
        if (resp.status !== 200) {
            error.innerText = "Error: Attempt to sign in failed";
            button.classList.remove("loading");
            return;
        }

        let asseResp;
        try {
            const decoded = await resp.json();
            asseResp = await startAuthentication(decoded["publicKey"]);
        } catch (e) {
            button.classList.remove("loading");
            console.log(e.name);
            if (e.name === "NotAllowedError") {
                error.innerText = "Error: Attempt to sign in was either cancelled or timed out";
            } else {
                error.innerText = e;
            }
            error.innerText = e;
            return;
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
            error.innerText = "Error: Attempt to sign in failed";
        }
    }
    button.addEventListener("click", attemptRegistration);
}