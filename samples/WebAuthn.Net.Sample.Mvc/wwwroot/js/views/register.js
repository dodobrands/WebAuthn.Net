(() => {
    const checkboxElements = [
        () => document.getElementById("allowed-algo-RS1"),
        () => document.getElementById("allowed-algo-RS512"),
        () => document.getElementById("allowed-algo-RS384"),
        () => document.getElementById("allowed-algo-RS256"),

        () => document.getElementById("allowed-algo-PS512"),
        () => document.getElementById("allowed-algo-PS384"),
        () => document.getElementById("allowed-algo-PS256"),

        () => document.getElementById("allowed-algo-ES512"),
        () => document.getElementById("allowed-algo-ES384"),
        () => document.getElementById("allowed-algo-ES256"),

        () => document.getElementById("allowed-algo-EdDSA"),
    ];
    const formElements = {
        userVerification: () => document.getElementById("webauthn-params-uv"),
        attachment: () => document.getElementById("webauthn-params-attachment"),
        discoverableCredential: () => document.getElementById("webauthn-params-discoverable"),
        attestation: () => document.getElementById("webauthn-params-attestation"),
        residentKey: () => document.getElementById("webauthn-params-rkey")
    };
    const elements = {
        registerInput: () => document.getElementById("webauthn-register-name"),
        registerButton: () => document.getElementById("webauthn-register-submit"),
        registerOptionsReset: () =>  document.getElementById("webauthn-params-submit"),
    };
    const defaultParams = {
        userVerification: "preferred",
        attachment: "unset",
        discoverableCredential: "unset",
        attestation: "none",
        residentKey: "unset",
        pubKeyCredParams: [
            -65535,
            -259,
            -258,
            -257,
            -39,
            -38,
            -37,
            -36,
            -35,
            -8,
            -7
        ],
    };
    const { initiateRegistration, submitRegistration } = API.Register;
    const {
        getState,
        setState,
        resetState,
        withState,
        ensureStateCreated
    } = createStateMethods({ key: localStateKeys.registrationParamsKey, defaultParams });

    // DOM Handlers
    const onRegisterButtonHandler = async (e) => {
        e.preventDefault();
        const registrationParameters = getState();
        const username = getElementValue(elements.registerInput());
        const initialData = await initiateRegistration({ registrationParameters, username });
        if (!initialData) return;
        const { options } = initialData;
        const publicKey = {
            ...options,
            challenge: coerceToArrayBuffer(options.challenge),
            user: {
                ...options.user,
                id: coerceToArrayBuffer(options.user.id),
            }
        };

        const response = await navigator.credentials.create({ publicKey });
        if (!response) return;

        const registrationResult = await submitRegistration({ response });
        if (!registrationResult) return;
        const { successful } = registrationResult;
        if (successful) {
            Alerts.registerSuccess();
            clearElementValue(elements.registerInput());
            return;
        }

        Alerts.failedToRegister();
    };

    // INIT
    document.addEventListener("DOMContentLoaded", () => {
        if (!isWebauthnAvailable()) {
            Alerts.webauthnIsNotAvailable();
            return;
        }
        ensureStateCreated();
        initializeForm({ state: getState(), setState, withState, formElements });
        initializeCheckboxArray({ withState, setState, initialValues: getState()["pubKeyCredParams"], stateKey: "pubKeyCredParams", checkboxElements });
        elements.registerButton().addEventListener("click", onRegisterButtonHandler);
        elements.registerOptionsReset().addEventListener("click", resetState);
    });
})();
