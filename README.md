# WebAuthn.Net

A production-ready, easy-to-use, extensible implementation of the [WebAuthn Level 3 standard](https://www.w3.org/TR/webauthn-3), passing the [FIDO conformance test](https://fidoalliance.org/certification/functional-certification/conformance/), for the server side of web applications on .NET 10 and .NET 11.

<a href="https://webauthn.dodo.dev"><img src="https://img.shields.io/badge/Demo-blue"/></a>
<a href="https://www.nuget.org/packages/WebAuthn.Net/"><img src="https://img.shields.io/badge/NuGet-blue"/></a>

## Documentation

The documentation for each project is described in its README.md file.

- [WebAuthn.Net](src/WebAuthn.Net)
- [WebAuthn.Net.Storage.SqlServer](src/WebAuthn.Net.Storage.SqlServer)
- [WebAuthn.Net.Storage.PostgreSql](src/WebAuthn.Net.Storage.PostgreSql)
- [WebAuthn.Net.Storage.MySql](src/WebAuthn.Net.Storage.MySql)
- [WebAuthn.Net.Storage.InMemory](src/WebAuthn.Net.Storage.InMemory)
- [WebAuthn.Net.OpenTelemetry](src/WebAuthn.Net.OpenTelemetry)

## Supported features

- ✅ [Passkeys](https://www.w3.org/TR/webauthn-3/#passkey) are supported out of the box
- ✅ Attestation API & verification (Register and verify credentials/authenticators)
- ✅ Assertion API & verification (Authenticate users)
- ✅ 100% completion of the entire [FIDO Conformance Test](https://fidoalliance.org/certification/functional-certification/conformance/), including all optional features
- ✅ [Demo application for performing the FIDO Conformance test](demo/WebAuthn.Net.Demo.FidoConformance)
- ✅ [Demo application demonstrating the capabilities of the library](demo/WebAuthn.Net.Demo.Mvc)
- ✅ Authenticators embedded in the device (FaceID, TouchID, Windows Hello)
- ✅ Roaming aka cross-platform authenticators (USB/NFC/BLE keys, for example Yubico)
- ✅ All current attestation statement formats
    - [packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation)
    - [tpm](https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation)
    - [android-key](https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation)
    - [fido-u2f](https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation)
    - [none](https://www.w3.org/TR/webauthn-3/#sctn-none-attestation)
    - [apple](https://www.w3.org/TR/webauthn-3/#sctn-apple-anonymous-attestation)
- ❌ The [android-safetynet](https://www.w3.org/TR/webauthn-3/#sctn-android-safetynet-attestation) attestation statement format is not supported, and a registration that uses it is rejected:
    - Google deprecated the SafetyNet Attestation API in 2022 and [turned it down completely in January 2025](https://developer.android.com/training/safetynet/attestation). Every call to the API now fails, so no authenticator can produce a valid `android-safetynet` attestation statement anymore.
    - The WebAuthn Level 3 specification marks the format as deprecated and expected to be removed. Its verification procedure relies on the SafetyNet online documentation, which no longer describes how to verify a response.
- ✅ All cryptographic algorithms required to pass the [FIDO Conformance Test](https://fidoalliance.org/certification/functional-certification/conformance/)
    - [RS1](https://www.rfc-editor.org/rfc/rfc8812.html#section-2)
    - [RS256](https://www.rfc-editor.org/rfc/rfc8812.html#section-2)
    - [RS384](https://www.rfc-editor.org/rfc/rfc8812.html#section-2)
    - [RS512](https://www.rfc-editor.org/rfc/rfc8812.html#section-2)
    - [PS256](https://www.rfc-editor.org/rfc/rfc8230.html#section-2)
    - [PS384](https://www.rfc-editor.org/rfc/rfc8230.html#section-2)
    - [PS512](https://www.rfc-editor.org/rfc/rfc8230.html#section-2)
    - [ES256](https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1)
    - [ES384](https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1)
    - [ES512](https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1)
    - [EdDSA](https://www.rfc-editor.org/rfc/rfc9053.html#section-2.2) (via [libsodium](https://github.com/jedisct1/libsodium), because .NET currently [doesn't support Ed25519](https://github.com/dotnet/runtime/issues/14741))
- ✅ [FIDO Metadata Service](https://fidoalliance.org/metadata) support: the metadata is verified and refreshed daily, a failed download is retried every minute, and the metadata can be [embedded in the application](src/WebAuthn.Net/README.md#embedding-the-metadata-in-the-application), so that the application starts and works even when the FIDO Metadata Service is unavailable
- ✅ Processing of each request with a single transaction
- ✅ Ready-to-use storage implementations
    - [Microsoft SQL Server](src/WebAuthn.Net.Storage.SqlServer)
    - [PostgreSQL](src/WebAuthn.Net.Storage.PostgreSql)
    - [MySQL](src/WebAuthn.Net.Storage.MySql)
    - [InMemory](src/WebAuthn.Net.Storage.InMemory) (for sample applications)
- ✅ Built-in metrics (with an [additional library](src/WebAuthn.Net.OpenTelemetry) for integrating WebAuthn.Net metrics with [OpenTelemetry](https://opentelemetry.io))
- ✅ Exceptionless design (avoid exceptions wherever possible)
- ✅ Designed with extensibility in mind (almost any library component can be overridden)
- ✅ Intellisense documentation

## Comparison with passkeys in ASP.NET Core Identity

Since .NET 10, ASP.NET Core Identity [supports passkeys](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/passkeys/). Microsoft positions this support as a way to sign in to applications built on ASP.NET Core Identity rather than as a general-purpose WebAuthn library. WebAuthn.Net is a general-purpose library: it implements the Relying Party side of WebAuthn, doesn't depend on ASP.NET Core Identity, and leaves users, sign-in and UI to the application.

The comparison is based on the source code of ASP.NET Core 10.0.15 and 11.0.0. Everything below applies to both versions.

| | ASP.NET Core Identity | WebAuthn.Net |
| --- | --- | --- |
| Integration | Part of ASP.NET Core Identity: requires `UserManager<TUser>` with a store that implements `IUserPasskeyStore<TUser>`. `SignInManager<TUser>` provides the ready-made flow, which keeps the ceremony state and signs the user in with the cookies of ASP.NET Core Identity. Without it, through `IPasskeyHandler<TUser>`, the application has to keep and protect the ceremony state itself. | Doesn't depend on ASP.NET Core Identity. The library identifies a user only by an opaque user handle, and the application signs the user in however it needs: with a cookie, with tokens for a SPA or a mobile app, or as an OpenID Connect server. |
| Attestation statements | Not verified by default: any attestation statement is accepted. The application can implement the `VerifyAttestationStatement` callback, which receives the raw attestation object and has to decode and verify it on its own. | `packed`, `tpm`, `android-key`, `fido-u2f`, `apple` and `none` are verified, including their certificate chains. `none` and self attestation can be rejected. By default, only TPM-bound keys and Android keys from a trusted execution environment (TEE or StrongBox) are accepted. |
| [FIDO Metadata Service](https://fidoalliance.org/metadata) | Not supported. | Built in: the metadata is verified, refreshed daily and can be embedded in the application. It provides the trust anchors for `packed`, `tpm`, `android-key` and `fido-u2f` attestation. |
| Revoked authenticators | Not detected. | If the authenticator model is identified through the FIDO metadata, registration is rejected when the metadata reports it as revoked, compromised or otherwise untrusted. Registration with `android-key` attestation is also rejected when its certificates are in [Google's revocation status list](https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status). |
| [FIDO conformance](https://fidoalliance.org/certification/functional-certification/conformance/) | The attestation tests of the FIDO Conformance Tools can't pass with the default settings: they expect invalid attestation statements to be rejected. | All FIDO2 server tests of the FIDO Conformance Tools pass: see the [results](demo/WebAuthn.Net.Demo.FidoConformance/docs/images/results.png) and the [demo application](demo/WebAuthn.Net.Demo.FidoConformance) for running them. |
| Credential public key algorithms | ES256, ES384, ES512, PS256, PS384, PS512, RS256, RS384, RS512. | The same, plus EdDSA (Ed25519) and RS1. |
| Ceremony options | Global: `IdentityPasskeyOptions`, with callbacks such as `ValidateOrigin` and `IsAllowedAlgorithm`. The methods that start a ceremony take only the user. `hints` and `attestationFormats` are always empty, and extensions are never sent. | Set for each ceremony, including `hints`, `attestation`, `attestationFormats`, extension inputs, and the accepted origins and top-level origins. |
| Signature counter | A counter that didn't increase always fails the authentication. | Fails the authentication by default. Optionally, the ceremony completes with `SignCountNotIncreased` set, so that the application can take it into account in its risk scoring. |
| Unexpected values in responses | Accepted: any `fmt`, and any `transports` values, which are stored and later sent back to the browser. The passkey code has no size limits of its own. | Rejected: unknown `fmt`, unknown or duplicate `transports` values, oversized responses. Each rejection is logged and counted. |
| Storage | EF Core (the `AspNetUserPasskeys` table of the Identity schema version 3) or a custom `IUserPasskeyStore<TUser>`. | Ready-made storage for SQL Server, PostgreSQL and MySQL, where each operation runs in a single transaction, in-memory storage for development, or a custom storage. |
| Monitoring | Metrics for passkey sign-ins and for adding, updating and removing passkeys. Failure reasons are logged only at the `Debug` level. | Metrics for both ceremonies, anomalies in the responses, the FIDO metadata and the Android status list, plus an [OpenTelemetry package](src/WebAuthn.Net.OpenTelemetry). Every failed ceremony is logged at the `Warning` level with the reason. |
| UI | The Blazor Web App template includes signing in with a passkey (with autofill) and a page to add, rename and delete passkeys. | Not included. The application builds its own UI and lists, renames and deletes the stored credentials itself. The [demo application](demo/WebAuthn.Net.Demo.Mvc) shows a minimal client. |

### When ASP.NET Core Identity is enough

- The application already uses ASP.NET Core Identity with its cookie sign-in (for example, it was created from the Blazor Web App template), and passkeys are one more way to sign in.
- The application accepts any authenticator and doesn't need attestation, which is typical for consumer applications.
- A ready-made UI and support from Microsoft matter more than control over the ceremonies.

### When WebAuthn.Net fits better

- The application doesn't use ASP.NET Core Identity: it has its own user model, issues tokens to a SPA or a mobile app, or is an OpenID Connect server.
- The application has to control which authenticators can be registered: for example, to accept only authenticators with a verifiable attestation in an enterprise or a regulated environment, or to keep out authenticator models with known vulnerabilities.
- The application needs options for each ceremony, EdDSA, or strict validation of responses that can be monitored with logs and metrics.
- The credentials have to be stored in SQL Server, PostgreSQL or MySQL without EF Core.

WebAuthn.Net can also be used in an application built on ASP.NET Core Identity: after a successful authentication ceremony, the application finds the user by the returned user handle and signs them in with `SignInManager<TUser>.SignInAsync`.

## Local development

### Required dependencies

- [.NET SDK 10.0.404+](https://dotnet.microsoft.com/en-us/download/dotnet/10.0)
- [.NET SDK 11.0.100+](https://dotnet.microsoft.com/en-us/download/dotnet/11.0)

## Tips for Contribution

Any contributions appreciated!
If you have an idea, feature request, or you find a bug – feel free to open new issue.

## Acknowledgements

WebAuthn.Net is built using the following wonderful tools

* [.NET](https://github.com/dotnet/runtime)
* [ASP.NET Core](https://github.com/dotnet/aspnetcore)
* [JetBrains Rider](https://www.jetbrains.com/rider)

WebAuthn.Net is inspired by the wonderful project [FIDO2 .NET Library (WebAuthn)](https://github.com/passwordless-lib/fido2-net-lib). However, WebAuthn.Net is not a fork, but a standalone project built entirely from scratch.
