(() => {
    const formElements = {
        userVerification: () => document.getElementById("webauthn-passwordless-params-uv"),
        attestation: () => document.getElementById("webauthn-passwordless-params-attestation"),
    };
    const elements = {
        authenticateInput: () => document.getElementById("webauthn-authenticate-name"),
        authenticateButton: () => document.getElementById("webauthn-authenticate-submit"),
        authenticateFormReset: () => document.getElementById("webauthn-passwordless-params-submit"),
        csrfElement: () => document.getElementById("webauthn-authenticate-request-token")
    };
    const defaultParams = {
        userVerification: "preferred",
        attestation: "none",
    };
    const {createAuthenticationOptions, completeAuthentication} = API.Passwordless;
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
        const csrf = getElementValue(elements.csrfElement());

        if (!isValidString(username)) {
            Alerts.usernameInputEmpty();
            clearElementValue(elements.registerInput());
            return;
        }

        const {userVerification, attestation} = getState();
        const options = await createAuthenticationOptions({username, attestation, userVerification, csrf});
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


        const attestationResult = await completeAuthentication({credential, csrf});
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
        ensureStateCreated();
        initializeForm({state: getState(), setState, withState, formElements});
        elements.authenticateButton().addEventListener("click", onAuthenticateButtonHandler);
        elements.authenticateFormReset().addEventListener("click", resetState);
    });
})();
