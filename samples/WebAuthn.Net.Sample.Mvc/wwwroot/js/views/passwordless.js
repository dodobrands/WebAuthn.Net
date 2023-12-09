(() => {
    const formElements = {
        userVerification: () => document.getElementById("webauthn-passwordless-params-uv"),
        attestation: () => document.getElementById("webauthn-passwordless-params-attestation"),
    };
    const elements = {
        authenticateInput: () => document.getElementById("webauthn-authenticate-name"),
        authenticateButton: () => document.getElementById("webauthn-authenticate-submit"),
        authenticateFormReset: () => document.getElementById("webauthn-passwordless-params-submit")
    };
    const defaultParams = {
        userVerification: "preferred",
        attestation: "none",
    };
    const {initiateAuthentication, submitAuthentication} = API.Passwordless;
    const {
        getState,
        setState,
        withState,
        resetState,
        ensureStateCreated
    } = createStateMethods({key: localStateKeys.passwordlessParamsKey, defaultParams});

    const onAuthenticateButtonHandler = async (e) => {
        e.preventDefault();
        const username = getElementValue(elements.authenticateInput());
        const {userVerification, attestation} = getState();
        const initialData = await initiateAuthentication({username, attestation, userVerification});
        if (!initialData) return;
        const {options} = initialData;
        const publicKey = {
            ...options,
            challenge: coerceToArrayBuffer(options.challenge),
            allowCredentials: (options.allowCredentials ?? []).map(x => ({...x, id: coerceToArrayBuffer(x.id)}))
        };
        const response = await navigator.credentials.get({publicKey});
        if (!response) return;

        const attestationResult = await submitAuthentication({username, response});
        if (!attestationResult) return;
        const {successful} = attestationResult;
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
        ensureStateCreated();
        initializeForm({state: getState(), setState, withState, formElements});
        elements.authenticateButton().addEventListener("click", onAuthenticateButtonHandler);
        elements.authenticateFormReset().addEventListener("click", resetState);
    });
})();
