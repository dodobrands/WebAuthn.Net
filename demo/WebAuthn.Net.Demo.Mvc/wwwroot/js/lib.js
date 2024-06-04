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
    const withState = (f) => (e) => f({state: getState(), event: e});
    const ensureStateCreated = () => {
        const state = getState();
        if (state) {
            const stateKeys = Object.keys(state);
            const initialStateKeys = Object.keys(defaultParams);
            // Ensure all keys in place!
            if (initialStateKeys.filter(x => !stateKeys.includes(x)).length === 0) return;
        }
        resetState();
    };
    return ({getState, setState, resetState, withState, ensureStateCreated});
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
const isValidString = (x) => typeof x === "string" && x.trim().length > 0;

const initializeForm = ({state, setState, withState, formElements}) => Object
    .keys(formElements)
    .forEach(key => {
        const element = formElements[key]();
        const onChange = ({state, event}) => setState({...state, [key]: event.target.value});
        element.value = state[key];
        element.addEventListener("change", withState(onChange));
    });

const initializeCheckboxArray = ({initialValues, setState, withState, checkboxElements, stateKey}) =>
    checkboxElements
        .forEach(f => {
            const element = f();
            const elementValueAsNumber = (x) => Number(x.value);
            const onChange = ({state, event}) => {
                const checkboxesState = state[stateKey];
                const value = elementValueAsNumber(event.target);
                const appendValue = () =>
                    !checkboxesState.includes(value) && setState({...state, [stateKey]: [...checkboxesState, value]});
                const removeValue = () =>
                    setState({...state, [stateKey]: checkboxesState.filter(x => x !== value)});

                event.target.checked ? appendValue() : removeValue();
            };

            const isChecked = initialValues.includes(elementValueAsNumber(element));
            isChecked && element.setAttribute("checked", true);
            element.addEventListener("change", withState(onChange));
        });

const makeJsonApiCall = async ({url, data, method, csrf}) => {
    const response = await fetch(url, {
        method,
        body: JSON.stringify(data),
        credentials: "include",
        headers: {
            "RequestVerificationToken": csrf ?? "",
            "content-type": "application/json"
        }
    });

    const content = await response.text();
    if (!response.ok) {
        alert(content);
        return undefined;
    }

    return isValidString(content) ? JSON.parse(content) : {};
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
    usernameInputEmpty: () => alert("Username input is empty"),
    credentialsGetApiNull: () => alert("navigator.credentials.get returned null"),
    credentialsCreateApiNull: () => alert("navigator.credentials.create returned null"),
    getAuthenticatorDataInvalid: () => alert("Invalid data from getAuthenticatorData() method. Expected ArrayBuffer"),
    getPublicKeyInvalid: () => alert("Invalid data from getPublicKey() method. Expected ArrayBuffer")
};

// API
const API = {
    Register: {
        createRegistrationOptions: async ({username, registrationParameters, csrf}) => {
            const url = "/registration/createregistrationoptions";
            const data = {
                username,
                registrationParameters,
                extensions: {}
            };
            return await makeJsonApiCall({url, data, method: "POST", csrf});
        },
        completeRegistration: async ({newCredential, csrf}) => {
            const url = "/registration/completeregistration";
            const clientExtensionResults = newCredential.getClientExtensionResults ?
                (newCredential.getClientExtensionResults() ?? {}) : {};

            let authenticatorData;
            if (newCredential.response.getAuthenticatorData) {
                const authData = newCredential.response.getAuthenticatorData();
                const isValid = authData instanceof ArrayBuffer;
                if (!isValid) {
                    Alerts.getAuthenticatorDataInvalid();
                    return;
                }
                authenticatorData = coerceToBase64Url(authData);
            }

            let publicKey;
            if (newCredential.response.getPublicKey) {
                const responsePublicKey = newCredential.response.getPublicKey();
                const isValid = responsePublicKey instanceof ArrayBuffer;
                if (responsePublicKey === null) {
                    publicKey = null;
                } else if (isValid) {
                    publicKey = coerceToBase64Url(responsePublicKey);
                } else {
                    Alerts.getPublicKeyInvalid();
                    return;
                }
            }

            const transports = newCredential.response.getTransports ?
                newCredential.response.getTransports() : undefined;

            const publicKeyAlgorithm = newCredential.response.getPublicKeyAlgorithm ?
                newCredential.response.getPublicKeyAlgorithm() : undefined;

            const data = {
                id: coerceToBase64Url(newCredential.rawId),
                rawId: coerceToBase64Url(newCredential.rawId),
                response: {
                    clientDataJson: coerceToBase64Url(newCredential.response.clientDataJSON),
                    authenticatorData,
                    transports,
                    publicKey,
                    publicKeyAlgorithm,
                    attestationObject: coerceToBase64Url(newCredential.response.attestationObject)
                },
                authenticatorAttachment: newCredential?.authenticatorAttachment,
                clientExtensionResults,
                type: newCredential.type
            };
            return await makeJsonApiCall({url, data, method: "POST", csrf});
        },
    },
    Passwordless: {
        createAuthenticationOptions: async ({username, userVerification, attestation, csrf}) => {
            const url = "/passwordless/createauthenticationoptions";
            const data = {
                username,
                userVerification,
                attestation,
                extensions: {}
            };
            return await makeJsonApiCall({url, data, method: "POST", csrf});
        },
        completeAuthentication: async ({credential, csrf}) => {
            const url = "/passwordless/completeauthentication";
            const clientExtensionResults = credential.getClientExtensionResults() ?? {};
            const userHandle = credential.response.userHandle ?
                coerceToBase64Url(credential.response.userHandle) : undefined;
            const attestationObject = credential.response.attestationObject ?
                coerceToBase64Url(credential.response.attestationObject) : undefined;

            const data = {
                id: coerceToBase64Url(credential.rawId),
                rawId: coerceToBase64Url(credential.rawId),
                response: {
                    clientDataJSON: coerceToBase64Url(credential.response.clientDataJSON),
                    authenticatorData: coerceToBase64Url(credential.response.authenticatorData),
                    signature: coerceToBase64Url(credential.response.signature),
                    userHandle,
                    attestationObject,
                },
                authenticatorAttachment: credential.authenticatorAttachment,
                clientExtensionResults,
                type: credential.type
            }
            return await makeJsonApiCall({url, data, method: "POST", csrf});
        },
    },
    Usernameless: {
        createAuthenticationOptions: async ({csrf}) => {
            const url = "/usernameless/createauthenticationoptions";
            const data = {
                extensions: {}
            };
            return await makeJsonApiCall({url, data, method: "POST", csrf});
        },
        completeAuthentication: async ({credential, csrf}) => {
            const url = "/usernameless/completeauthentication";
            const clientExtensionResults = credential.getClientExtensionResults ?
                (credential.getClientExtensionResults() ?? {}) : undefined;
            const userHandle = credential.response.userHandle ?
                coerceToBase64Url(credential.response.userHandle) : undefined;
            const attestationObject = credential.response.attestationObject ?
                coerceToBase64Url(credential.response.attestationObject) : undefined;
            const data = {
                id: coerceToBase64Url(credential.rawId),
                rawId: coerceToBase64Url(credential.rawId),
                response: {
                    clientDataJSON: coerceToBase64Url(credential.response.clientDataJSON),
                    authenticatorData: coerceToBase64Url(credential.response.authenticatorData),
                    signature: coerceToBase64Url(credential.response.signature),
                    userHandle,
                    attestationObject,
                },
                authenticatorAttachment: credential.authenticatorAttachment,
                clientExtensionResults,
                type: credential.type
            }
            return await makeJsonApiCall({url, data, method: "POST", csrf});
        }
    }
}
