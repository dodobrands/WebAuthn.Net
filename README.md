# WebAuthn.Net

A production-ready, easy-to-use, extensible implementation of the [WebAuthn Level 3 standard](https://www.w3.org/TR/2023/WD-webauthn-3-20230927/), passing the [FIDO conformance test](https://fidoalliance.org/certification/functional-certification/conformance/), for the server side of web applications on .NET 6 and .NET 8.

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

- ✅ [Passkeys](https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#passkey) are supported out of the box
- ✅ Attestation API & verification (Register and verify credentials/authenticators)
- ✅ Assertion API & verification (Authenticate users)
- ✅ 100% completion of the entire [FIDO Conformance Test](https://fidoalliance.org/certification/functional-certification/conformance/), including all optional features
- ✅ [Demo application for performing the FIDO Conformance test](demo/WebAuthn.Net.Demo.FidoConformance)
- ✅ [Demo application demonstrating the capabilities of the library](demo/WebAuthn.Net.Demo.Mvc)
- ✅ Authenticators embedded in the device (FaceID, TouchID, Windows Hello)
- ✅ Roaming aka cross-platform authenticators (USB/NFC/BLE keys, for example Yubico)
- ✅ All current attestation statement formats
    - [packed](https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-packed-attestation)
    - [tpm](https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-tpm-attestation)
    - [android-key](https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-key-attestation)
    - [android-safetynet](https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-safetynet-attestation)
    - [fido-u2f](https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-fido-u2f-attestation)
    - [none](https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-none-attestation)
    - [apple](https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-apple-anonymous-attestation)
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

## Local development

### Required dependencies

- [.NET SDK 6.0.422+](https://dotnet.microsoft.com/en-us/download/dotnet/6.0)
- [.NET SDK 8.0.205+](https://dotnet.microsoft.com/en-us/download/dotnet/8.0)

## Tips for Contribution

Any contributions appreciated!
If you have an idea, feature request, or you find a bug – feel free to open new issue.

## Acknowledgements

WebAuthn.Net is built using the following wonderful tools

* [.NET](https://github.com/dotnet/runtime)
* [ASP.NET Core](https://github.com/dotnet/aspnetcore)
* [JetBrains Rider](https://www.jetbrains.com/rider)

WebAuthn.Net is inspired by the wonderful project [FIDO2 .NET Library (WebAuthn)](https://github.com/passwordless-lib/fido2-net-lib). However, WebAuthn.Net is not a fork, but a standalone project built entirely from scratch.
