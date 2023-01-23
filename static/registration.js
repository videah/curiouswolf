window.onload = function() {
    const { startRegistration } = SimpleWebAuthnBrowser;

    const button = document.getElementById("register-button");
    const error = document.getElementById("error-label");
    const username = document.getElementById("username");

    let redirecting = false;

    async function displayError(e) {
        console.log(e);
        button.classList.remove("loading");
        error.innerText = await e.text();
    }

    async function attemptRegistration() {
        error.innerText = "";
        button.classList.add("loading");

        if (username.value === "") {
            error.innerText = "Username cannot be empty";
            button.classList.remove("loading");
            return;
        }

        const resp = await fetch("/auth/register_start/" + username.value, {method: "POST"});
        if (resp.status === 200) {
            let attResp;
            try {
                const decoded = await resp.json()
                attResp = await startRegistration(decoded["publicKey"]);
            } catch (e) {
                return displayError(e);
            }

            const url = "/auth/register_finish";
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

    button.addEventListener("click", () => {if (!redirecting) { attemptRegistration() }});
    username.addEventListener("keydown", (e) => {if (e.key === "Enter") { attemptRegistration() }});
}