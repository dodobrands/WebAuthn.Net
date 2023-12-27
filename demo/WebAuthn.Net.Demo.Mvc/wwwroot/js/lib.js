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
        credentials: "same-origin",
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
    credentialsCreateApiNull: () => alert("navigator.credentials.create returned null")
};

// API
const API = {
    Register: {
        initiateRegistration: async ({username, registrationParameters, csrf}) => {
            const url = "/registration/createregistrationoptions";
            const data = {
                username,
                registrationParameters,
                extensions: {}
            };
            return await makeJsonApiCall({url, data, method: "POST", csrf});
        },
        submitRegistration: async ({response, csrf}) => {
            const url = "/registration/completeregistration";
            const data = {
                authenticatorAttachment: "cross-platform",
                id: coerceToBase64Url(response.rawId),
                rawId: coerceToBase64Url(response.rawId),
                type: response.type,
                response: {
                    attestationObject: coerceToBase64Url(response.response.attestationObject),
                    clientDataJson: coerceToBase64Url(response.response.clientDataJSON)
                },
                clientExtensionResults: {}
            };
            return await makeJsonApiCall({url, data, method: "POST", csrf});
        },
    },
    Passwordless: {
        initiateAuthentication: async ({username, userVerification, attestation, csrf}) => {
            const url = "/passwordless/createauthenticationoptions";
            const data = {
                username,
                userVerification,
                attestation
            };
            return await makeJsonApiCall({url, data, method: "POST", csrf});
        },
        submitAuthentication: async ({username, response, csrf}) => {
            const url = "/passwordless/completeauthentication";
            const data = {
                id: coerceToBase64Url(response.rawId),
                rawId: coerceToBase64Url(response.rawId),
                username,
                type: response.type,
                clientExtensionResults: response.getClientExtensionResults(),
                response: {
                    userHandle: coerceToBase64Url(response.response.userHandle),
                    authenticatorData: coerceToBase64Url(response.response.authenticatorData),
                    clientDataJSON: coerceToBase64Url(response.response.clientDataJSON),
                    signature: coerceToBase64Url(response.response.signature),
                }
            }
            return await makeJsonApiCall({url, data, method: "POST", csrf});
        },
    },
    Usernameless: {
        initiateAuthentication: async ({csrf}) => {
            const url = "/usernameless/createauthenticationoptions";
            const data = {
                extensions: {}
            };
            return await makeJsonApiCall({url, data, method: "POST", csrf});
        },
        submitAuthentication: async ({response, csrf}) => {
            const url = "/usernameless/completeauthentication";
            const data = {
                id: coerceToBase64Url(response.rawId),
                rawId: coerceToBase64Url(response.rawId),
                type: response.type,
                clientExtensionResults: response.getClientExtensionResults(),
                response: {
                    userHandle: coerceToBase64Url(response.response.userHandle),
                    authenticatorData: coerceToBase64Url(response.response.authenticatorData),
                    clientDataJSON: coerceToBase64Url(response.response.clientDataJSON),
                    signature: coerceToBase64Url(response.response.signature),
                }
            }
            return await makeJsonApiCall({url, data, method: "POST", csrf});
        }
    }
}
