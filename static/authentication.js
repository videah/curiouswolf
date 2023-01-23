window.onload = function() {
    const { startAuthentication } = SimpleWebAuthnBrowser;

    const button = document.getElementById("sign-in-button");
    const error = document.getElementById("error-label");
    const username = document.getElementById("username");

    let redirecting = false;

    async function displayError(e) {
        console.log(e);
        button.classList.remove("loading");
        try {
            error.innerText = await e.text();
        } catch {
            if (e.name === "NotAllowedError") {
                error.innerText = "Attempt to sign in was either cancelled or timed out";
            } else {
                error.innerText = e;
            }
        }

    }

    async function attemptAuthentication() {
        error.innerText = "";
        button.classList.add("loading");

        const username = document.getElementById("username");

        if (username.value === "") {
            error.innerText = "Username cannot be empty";
            button.classList.remove("loading");
            return;
        }

        const resp = await fetch("/auth/authenticate_start/" + username.value, {method: "POST"});
        if (resp.status === 200) {
            let attResp;
            try {
                const decoded = await resp.json()
                attResp = await startAuthentication(decoded["publicKey"]);
            } catch (e) {
                return displayError(e);
            }

            const url = "/auth/authenticate_finish";
            const verificationResp = await fetch(url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(attResp),
            });

            if (verificationResp.status === 200) {
                const success = document.getElementById("button-success");
                const label = document.getElementById("button-label");

                button.classList.remove("~info");
                button.classList.remove("loading");
                button.classList.add("~positive");

                label.classList.add("hidden");
                success.classList.remove("hidden");

                await new Promise(r => setTimeout(r, 300));
                document.location.href = "/";
            } else {
                return displayError(verificationResp);
            }
        } else {
            return displayError(resp);
        }
    }

    button.addEventListener("click", () => {if (!redirecting) { attemptAuthentication() }});
    username.addEventListener("keydown", (e) => {if (e.key === "Enter") { attemptAuthentication() }});
}