(() => {
    const {createAuthenticationOptions, completeAuthentication} = API.Usernameless;
    const elements = {
        authenticateBtn: () => document.getElementById("webauthn-usernameless-submit"),
        csrfElement: () => document.getElementById("webauthn-usernameless-request-token")
    };
    // DOM Handlers
    const onAuthenticateButtonHandler = async (e) => {
        e.preventDefault();
        const csrf = getElementValue(elements.csrfElement());
        const options = await createAuthenticationOptions({csrf});
        if (!options) return;
        const publicKey = {
            ...options,
            challenge: coerceToArrayBuffer(options.challenge),
            allowCredentials: (options.allowCredentials ?? []).map(x => ({...x, id: coerceToArrayBuffer(x.id)}))
        };

        let credential;
        try {
            credential = await navigator.credentials.get({publicKey});
            if (!credential) {
                Alerts.credentialsGetApiNull();
                return;
            }
        } catch (e) {
            alert(e.message);
            return;
        }


        const attestationResult = await completeAuthentication({csrf, credential});
        if (!attestationResult) return;
        const {hasError} = attestationResult;
        if (hasError) {
            Alerts.failedToAuthenticate();
            return;
        }
        location.reload();
    };

    // INIT
    document.addEventListener("DOMContentLoaded", () => {
        if (!isWebauthnAvailable()) {
            Alerts.webauthnIsNotAvailable();
            return;
        }

        elements.authenticateBtn().addEventListener("click", onAuthenticateButtonHandler);
    });
})();
