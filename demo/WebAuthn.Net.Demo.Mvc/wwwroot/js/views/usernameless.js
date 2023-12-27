(() => {
    const {initiateAuthentication, submitAuthentication} = API.Usernameless;
    const elements = {
        authenticateBtn: () => document.getElementById("webauthn-usernameless-submit"),
        csrfElement: () => document.getElementById("webauthn-usernameless-request-token")
    };
    // DOM Handlers
    const onAuthenticateButtonHandler = async (e) => {
        e.preventDefault();
        const csrf = getElementValue(elements.csrfElement());
        const options = await initiateAuthentication({csrf});
        if (!options) return;
        const publicKey = {
            ...options,
            challenge: coerceToArrayBuffer(options.challenge),
            allowCredentials: (options.allowCredentials ?? []).map(x => ({...x, id: coerceToArrayBuffer(x.id)}))
        };

        let response;
        try {
            response = await navigator.credentials.get({publicKey});
            if (!response) {
                Alerts.credentialsGetApiNull();
                return;
            }
        } catch (e) {
            alert(e.message);
            return;
        }


        const attestationResult = await submitAuthentication({csrf, response});
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
