# WebAuthn.Net

The main library, which contains the key logic, as well as abstractions for storage. Everything else is additions to it.

## Key concepts

The WebAuthn specification defines two main processes that occur during interaction with the user. They are called the registration and authentication ceremonies.

### Registration ceremony

Also, this process can be referred to as "Registering a New Credential".

The essence of the process is to associate a public key with the user account.

1. Generate a random value (`challenge`) and read the identifier of the authenticated user (`userHandle`)
2. Pass these values to the frontend as options in the method `navigator.credentials.create()`
3. Perform validation of the result of the method `navigator.credentials.create()` on the backend, during which the `credentialId` will be obtained
4. If the validation was successful - create an association between `userHandle` and `credentialId` on the backend

As a result of this operation, an association is formed between the user's account and a specific public key, stored both on the backend and on the authenticator device. In the future, these data will be used for user authentication.

### Authentication ceremony

Also, this process can be referred to as "Verifying an Authentication Assertion".

The essence of the process comes down to comparing the `credentialId` and `userHandle` (in the case of Passkeys), which were created during the registration ceremony, with the data stored on the backend to authenticate the user.

1. Generate a random value (`challenge`) and optionally (in the case of Passkeys) read the existing user's public keys
2. Pass these values to the frontend as options in the method `navigator.credentials.get()`
3. Validate the result of the `navigator.credentials.get()` method on the backend by comparing the `credentialId` and `userHandle` (in the case of Passkeys) with the values created during the registration ceremony.
4. If the validation was successful - authenticate the user.

This is a highly simplified description of the processes. To familiarize yourself with what is actually happening, it is strongly recommended to read the specification.

## Key concepts in practice

For practical work with key concepts in WebAuthn.Net, there are 2 interfaces: `IRegistrationCeremonyService` and `IAuthenticationCeremonyService`.

They are built on similar principles:

- The `BeginCeremonyAsync` method, which takes parameters for generating options for the corresponding ceremony and returns:
    - An **identifier of the corresponding ceremony**, which you need to handle in such a way that only the backend has access to its raw value. For this, place it in one of the following locations:
        - in a cookie (encrypt the identifier and set `httponly` and `secure` properties to the cookies)
        - in a session (store the value on the backend, in any convenient way)
    - Options in the form of a model suitable for serialization to JSON, which can later be passed to the corresponding API call - `navigator.credentials.create()` or `navigator.credentials.get()`.
- The `CompleteCeremonyAsync` method, which takes the result of `navigator.credentials.create()` or `navigator.credentials.get()` and returns the result of the ceremony, which allows you to find out whether it was completed successfully, as well as depending on the ceremony - additional parameters that can be used to improve security and user experience.

In other words, there are two interfaces, each with two methods, and they encapsulate all the logic needed to implement WebAuthn (Passkeys).
