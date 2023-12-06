(() => {
    const { initiateAuthentication, submitAuthentication } = API.Usernameless;
    const elements = {
        authenticateBtn: () => document.getElementById("webauthn-usernameless-submit"),
    };
    // DOM Handlers
    const onAuthenticateButtonHandler = async (e) => {
        e.preventDefault();
        const initialData = await initiateAuthentication();
        if (!initialData) return;
        const { options } = initialData;
        const publicKey = {
            ...options,
            challenge: coerceToArrayBuffer(options.challenge),
            allowCredentials: (options.allowCredentials ?? []).map(x => ({...x,  id: coerceToArrayBuffer(x.id)}))
        };
        const response = await navigator.credentials.get({ publicKey });
        if (!response) return;

        const attestationResult = await submitAuthentication({ response });
        if (!attestationResult) return;
        const { successful } = attestationResult;
        if (!successful) {
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
