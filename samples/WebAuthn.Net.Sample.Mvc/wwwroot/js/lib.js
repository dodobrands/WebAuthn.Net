// State manager
const localStateKeys = {
    registrationParamsKey: "webauthn-registration-params",
    passwordlessParamsKey: "webauthn-passwordless-params"
}

const createStateMethods = ({key, defaultParams}) => {
    const getState = () => {
        const value = localStorage.getItem(key);
        return value ? JSON.parse(value) : undefined;
    };
    const setState = (x) => localStorage.setItem(key, JSON.stringify(x));
    const resetState = () => setState(JSON.parse(JSON.stringify(defaultParams)));
    const withState = (f) => (e) => f({ state: getState(), event: e });
    const ensureStateCreated = () => !getState() && resetState();
    return ({ getState, setState, resetState, withState, ensureStateCreated });
};

// Utils
const coerceToArrayBuffer = (x) => {
    const fix = x.replace(/-/g, "+").replace(/_/g, "/");
    return Uint8Array.from(window.atob(fix), c => c.charCodeAt(0));
};
const coerceToBase64Url = (x) => {
    const str = new Uint8Array(x)
        .reduce((acc, x) => acc += String.fromCharCode(x), "");
    return window.btoa(str)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=*$/g, "");
};
const clearElementValue = (x) => x.value = "";
const getElementValue = (x) => x.value ?? "";

const initializeForm = ({ state, setState, withState, formElements }) => Object
    .keys(formElements)
    .forEach(key => {
        const element = formElements[key]();
        const onChange = ({state, event}) => setState({...state, [key]: event.target.value});
        element.value = state[key];
        element.addEventListener("change", withState(onChange));
    });

const makeJsonApiCall = async ({url, data, method}) => {
    const response = await fetch(url, {
        method,
        body: JSON.stringify(data),
        credentials: "same-origin",
        headers: {
            "content-type": "application/json"
        }
    });

    if (response.ok) {
        return await response.json();
    }

    alert(await response.text());
    return undefined;
};
const isWebauthnAvailable = () => {
    const missingWebauthnApis = window.PublicKeyCredential === undefined
        || typeof window.PublicKeyCredential !== "function"
        || typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== "function";

    return window.isSecureContext && !missingWebauthnApis;
};

const Alerts = {
    failedToAuthenticate: () => alert("Failed to authenticate user, check server logs"),
    failedToRegister: () => alert("Failed to register user, check server logs"),
    webauthnIsNotAvailable: () => alert("Browser doesn't support Webauthn API"),
    registerSuccess: () => alert("User registered!"),
};

// API
const API = {
    Register: {
        initiateRegistration: async ({username, registrationParameters}) => {
            const url = "/Register/BeginRegisterCeremony";
            const data = {
                username,
                registrationParameters,
                extensions: {}
            };
            return await makeJsonApiCall({ url, data, method: "POST" });
        },
        submitRegistration: async ({ response }) => {
            const url = "/Register/RegisterCeremony";
            const data = {
                id: coerceToBase64Url(response.rawId),
                type: response.type,
                response: {
                    attestationObject: coerceToBase64Url(response.response.attestationObject),
                    clientDataJson: coerceToBase64Url(response.response.clientDataJSON)
                }
            };
            return await makeJsonApiCall({ url, data, method: "POST" });
        },
    },
    Passwordless: {
        initiateAuthentication: async ({ username, userVerification, attestation }) => {
            const url = "/Passwordless/BeginAuthenticationCeremony";
            const data = {
                username,
                userVerification,
                attestation
            };
            return await makeJsonApiCall({ url, data, method: "POST" });
        },
        submitAuthentication: async ({ username, response }) => {
            const url = "/Passwordless/AuthenticationCeremony";
            const data = {
                id: coerceToBase64Url(response.rawId),
                username,
                type: response.type,
                extensions: response.getClientExtensionResults(),
                response: {
                    userHandle: coerceToBase64Url(response.response.userHandle),
                    authenticatorData: coerceToBase64Url(response.response.authenticatorData),
                    clientDataJSON: coerceToBase64Url(response.response.clientDataJSON),
                    signature: coerceToBase64Url(response.response.signature),
                }
            }
            return await makeJsonApiCall({ url, data, method: "POST" });
        },
    },
    Usernameless : {
        initiateRegistration: async () => {
            const url = "/Usernameless/BeginRegisterCeremony";
            const data = {
                registrationParameters: {},
                extensions: {}
            };
            return await makeJsonApiCall({ url, data, method: "POST" });
        },
        submitRegistration: async ({ response }) => {
            const url = "/Usernameless/RegisterCeremony";
            const data = {
                id: coerceToBase64Url(response.rawId),
                type: response.type,
                response: {
                    attestationObject: coerceToBase64Url(response.response.attestationObject),
                    clientDataJson: coerceToBase64Url(response.response.clientDataJSON)
                }
            };
            return await makeJsonApiCall({ url, data, method: "POST" });
        },
        initiateAuthentication: async () => {
            const url = "/Usernameless/BeginAuthenticationCeremony";
            const data = {};
            return await makeJsonApiCall({ url, data, method: "POST" });
        },
        submitAuthentication: async ({ response }) => {
            const url = "/Usernameless/AuthenticationCeremony";
            const data = {
                id: coerceToBase64Url(response.rawId),
                type: response.type,
                extensions: response.getClientExtensionResults(),
                response: {
                    userHandle: coerceToBase64Url(response.response.userHandle),
                    authenticatorData: coerceToBase64Url(response.response.authenticatorData),
                    clientDataJSON: coerceToBase64Url(response.response.clientDataJSON),
                    signature: coerceToBase64Url(response.response.signature),
                }
            }
            return await makeJsonApiCall({ url, data, method: "POST" });
        }
    }
}
