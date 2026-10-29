# WebAuthn.Net

The main library, which contains the key logic, as well as abstractions for storage. Everything else is additions to it.

## Quickstart

### Integration with databases

For a quick and easy start, WebAuthn.Net provides ready-to-use storage implementations for different databases as separate packages, containing a minimal set of dependencies

#### Microsoft SQL Server

To connect WebAuthn.Net with a ready-to-use storage implementation for Microsoft SQL Server, you need to install the [`WebAuthn.Net.Storage.SqlServer`](../WebAuthn.Net.Storage.SqlServer) package and call the corresponding extension method.

```csharp
services.AddWebAuthnSqlServer(
    configureSqlServer: sqlServer =>
    {
        sqlServer.ConnectionString = "CONNECTION_STRING_HERE";
    });
```

[Documentation detailing the creation of a schema](../WebAuthn.Net.Storage.SqlServer) in the database is contained in the `README.md` of the corresponding package.

#### PostgreSQL

To connect WebAuthn.Net with a ready-to-use storage implementation for PostgreSQL, you need to install the [`WebAuthn.Net.Storage.PostgreSql`](../WebAuthn.Net.Storage.PostgreSql) package and call the corresponding extension method.

```csharp
services.AddWebAuthnPostgreSql(
    configurePostgreSql: postgresql =>
    {
        postgresql.ConnectionString = "CONNECTION_STRING_HERE";
    });
```

[Documentation detailing the creation of a schema](../WebAuthn.Net.Storage.PostgreSql) in the database is contained in the `README.md` of the corresponding package.

#### MySQL

To connect WebAuthn.Net with a ready-to-use storage implementation for MySQL, you need to install the [`WebAuthn.Net.Storage.MySql`](../WebAuthn.Net.Storage.MySql) package and call the corresponding extension method.

```csharp
services.AddWebAuthnMySql(
    configureMySql: mysql =>
    {
        mysql.ConnectionString = "CONNECTION_STRING_HERE";
    });
```

[Documentation detailing the creation of a schema](../WebAuthn.Net.Storage.MySql) in the database is contained in the `README.md` of the corresponding package.

### Registration

#### Creating registration ceremony options

```csharp
var result = await _registrationCeremonyService.BeginCeremonyAsync(
    httpContext: HttpContext,
    request: new BeginRegistrationCeremonyRequest(
        origins: null,
        topOrigins: null,
        rpDisplayName: "My Awesome Web Service",
        user: new PublicKeyCredentialUserEntity(
            name: "User Name",
            id: new byte[] { 0x01, 0x03, 0x03, 0x07 },
            displayName: "User Display Name"),
        challengeSize: 32,
        pubKeyCredParams: new CoseAlgorithm[]
        {
            CoseAlgorithm.ES256,
            CoseAlgorithm.ES384,
            CoseAlgorithm.ES512,
            CoseAlgorithm.RS256,
            CoseAlgorithm.RS384,
            CoseAlgorithm.RS512,
            CoseAlgorithm.PS256,
            CoseAlgorithm.PS384,
            CoseAlgorithm.PS512,
            CoseAlgorithm.EdDSA
        },
        timeout: 300_000,
        excludeCredentials: RegistrationCeremonyExcludeCredentials.AllExisting(),
        authenticatorSelection: new AuthenticatorSelectionCriteria(
            authenticatorAttachment: null,
            residentKey: ResidentKeyRequirement.Required,
            requireResidentKey: true,
            userVerification: UserVerificationRequirement.Required),
        hints: null,
        attestation: null,
        attestationFormats: null,
        extensions: null),
    cancellationToken: cancellationToken);
```

You can change any options and parameters at your discretion.

The `origins` and `topOrigins` are optional parameters that define which `origin` and `topOrigin` values of the client data the ceremony accepts. By default, the only accepted origin is the origin of the current request, and the ceremony is not expected to run in an iframe embedded by another site. See [Origin validation](#origin-validation) for the details and for when to override them.

The `timeout` is passed to the browser as a hint, and on the server it also sets the lifetime of the ceremony, see [Ceremony lifetime](#ceremony-lifetime).

#### Completing the registration ceremony

```csharp
var result = await _registrationCeremonyService.CompleteCeremonyAsync(
    httpContext: HttpContext,
    request: new CompleteRegistrationCeremonyRequest(
        registrationCeremonyId: registrationCeremonyId,
        description: "Windows Hello Authentication",
        response: model),
    cancellationToken: cancellationToken);
```

In this example, `model` is the result of the `navigator.credentials.create()` function serialized to JSON

### Authentication

#### Creating authentication ceremony options

```csharp
var result = await _authenticationCeremonyService.BeginCeremonyAsync(
    httpContext: HttpContext,
    request: new BeginAuthenticationCeremonyRequest(
        origins: null,
        topOrigins: null,
        userHandle: new byte[] { 0x01, 0x03, 0x03, 0x07 },
        challengeSize: 32,
        timeout: 300_000,
        allowCredentials: AuthenticationCeremonyIncludeCredentials.AllExisting(),
        userVerification: UserVerificationRequirement.Required,
        hints: null,
        extensions: null),
    cancellationToken: cancellationToken);
```

As in the example with the registration ceremony, you can change all the parameters at your own discretion.

The `origins` and `topOrigins` work the same way as in the registration ceremony (see [Origin validation](#origin-validation)), and so does the `timeout` (see [Ceremony lifetime](#ceremony-lifetime)).

The `userHandle` is optional for the authentication ceremony, but the WebAuthn specification contains additional comments on this (the comments relate to the combination of `userHandle` and `allowCredentials`):
> If the user account to authenticate is not already identified, then the relying party may leave this member empty or unspecified. In this case, only discoverable credentials will be utilized in this authentication ceremony, and the user account may be identified by the userHandle of the resulting AuthenticatorAssertionResponse.

Discoverable Credential is a synonym for Passkey.

#### Completing the authentication ceremony

```csharp
var result = await _authenticationCeremonyService.CompleteCeremonyAsync(
    httpContext: HttpContext,
    request: new CompleteAuthenticationCeremonyRequest(
        authenticationCeremonyId: authenticationCeremonyId,
        response: model),
    cancellationToken: cancellationToken);
```

In this example, `model` is the result of the `navigator.credentials.get()` function serialized to JSON.

## Key concepts

The WebAuthn specification defines two main processes that occur during interaction with the user. They are called the registration and authentication ceremonies.

### Registration ceremony

This process is detailed in the ["Registering a New Credential"](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential) section of the WebAuthn specification.

The purpose of the process is to associate a public key with the user account.

1. Generate a random value (`challenge`) and read the identifier of the authenticated user (`userHandle`) on the backend
2. Pass these values to the frontend as options in the method `navigator.credentials.create()`
3. Pass the result of the `navigator.credentials.create()` method to the backend, where its validation will be performed
4. Obtain the `credentialId` during the validation process
5. If the validation was successful - create an association between `userHandle` and `credentialId` on the backend

As a result of this operation, an association is formed between the user's account and a specific public key, stored both on the backend and on the authenticator device. In the future, these data will be used for user authentication.

### Authentication ceremony

This process is detailed in the ["Verifying an Authentication Assertion"](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion) section of the WebAuthn specification.

The purpose of the process comes down to comparing the `credentialId` and `userHandle` (in the case of Passkeys), which were created during the registration ceremony, with the data stored on the backend to authenticate the user.

1. Generate a random value (`challenge`) and optionally (in the case of Passkeys) read the existing user's public keys
2. Pass these values to the frontend as options in the method `navigator.credentials.get()`
3. Pass the result of executing `navigator.credentials.get()` to the backend, where validation will be performed
4. Validate the result of the `navigator.credentials.get()` method on the backend by comparing the `credentialId` and `userHandle` (in the case of Passkeys) with the values created during the registration ceremony
4. If the validation was successful - authenticate the user

This is a highly simplified description of the processes. To familiarize yourself with what is actually happening, it is strongly recommended to read the specification.

## Key concepts in practice

For practical work with key concepts in WebAuthn.Net, there are 2 interfaces: `IRegistrationCeremonyService` and `IAuthenticationCeremonyService`.

They are built on similar principles:

- The `BeginCeremonyAsync` method, which takes parameters for generating options for the corresponding ceremony and returns:
    - An identifier of the corresponding ceremony, which you need to handle in such a way that only the backend has access to its raw value. For this, place it in one of the following locations:
        - in a cookie (encrypt the identifier and set `httponly` and `secure` properties to the cookies)
        - in a session (store the value on the backend, in any convenient way)
    - Options in the form of a model suitable for serialization to JSON, which can later be passed to the corresponding API call - `navigator.credentials.create()` or `navigator.credentials.get()`.
- The `CompleteCeremonyAsync` method, which takes the result of `navigator.credentials.create()` or `navigator.credentials.get()` and returns the result of the ceremony, which allows you to find out whether it was completed successfully, as well as depending on the ceremony - additional parameters that can be used to improve security and user experience.

In other words, there are two interfaces, each with two methods, and they encapsulate all the logic needed to implement WebAuthn (Passkeys).

## Origin validation

When a ceremony is completed, WebAuthn.Net checks the `origin`, `crossOrigin` and `topOrigin` members of the client data, as required by steps 9-11 of ["Registering a New Credential"](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential) and steps 12-14 of ["Verifying an Authentication Assertion"](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion), following the guidance of ["Validating the origin of a credential"](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin). The expected values are set by the `origins` and `topOrigins` parameters of `BeginCeremonyAsync` and are stored together with the ceremony.

### Origins

The `origin` has to be exactly equal to one of the allowed origins.

- If `origins` is `null`, the only allowed origin is the origin of the current request: the scheme, the host and the port of `HttpRequest` (for example, `https://example.org` or `https://example.org:8443`), computed by `IRelyingPartyOriginProvider`. If the application runs behind a reverse proxy, make sure that the request contains the scheme and the host that the browser sees (for example, with the [Forwarded Headers Middleware](https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/proxy-load-balancer)), or pass the origins explicitly.
- Pass the origins explicitly if the ceremonies are performed on several origins (for example, with [related origin requests](https://www.w3.org/TR/webauthn-3/#sctn-related-origins)) or by a native application.
    - The constructor of `RegistrationCeremonyOriginParameters` and `AuthenticationCeremonyOriginParameters` that accepts `Uri[]` takes only the scheme, the host and the port of each address and serializes them the way the browser does: in lower case, without a path and without the default port, with an internationalized domain name in Punycode.
    - The constructor that accepts `string[]` takes the values as they are, so each of them has to be written exactly as the client reports it: `https://example.org`, but not `https://example.org/` or `https://Example.org`. Use it for the origins of native applications.

The RP ID doesn't depend on these parameters. By default, it is the host of the current request, computed by `IRelyingPartyIdProvider`.

### Top origins

The `crossOrigin` and `topOrigin` members show whether the ceremony was performed in an iframe that is not same-origin with its ancestors, and what the origin of the top-level page was. Clients that implement WebAuthn Level 3 report `topOrigin` together with `crossOrigin: true`, while older clients report only `crossOrigin`.

| Client data                                                | `topOrigins` is `null` (default) | `topOrigins` is specified             |
|------------------------------------------------------------|----------------------------------|---------------------------------------|
| `crossOrigin` is absent or `false`, `topOrigin` is absent  | accepted                         | accepted                              |
| `crossOrigin: true` without `topOrigin`                    | rejected                         | accepted                              |
| `topOrigin` is equal to `origin`                           | accepted                         | accepted if it is one of `topOrigins` |
| any other `topOrigin`                                      | rejected                         | accepted if it is one of `topOrigins` |

- By default, the Relying Party doesn't expect to be embedded by other sites. A ceremony in a cross-origin iframe is accepted only when the client confirms that the top-level page has the same origin as the ceremony itself, as the specification suggests for "a web application that does not wish to be embedded in a cross-origin iframe".
- If your pages are embedded in iframes on other sites, pass the origins of their top-level pages in `topOrigins`. The list replaces the default rule: if the ceremony can also run in an iframe under a top-level page of your own origin, add that origin to the list as well.

The embedding page also has to allow the iframe to use the API, for example `<iframe src="..." allow="publickey-credentials-create; publickey-credentials-get">` (see ["Using Web Authentication within iframe elements"](https://www.w3.org/TR/webauthn-3/#sctn-iframe-guidance)).

## Ceremony lifetime

The `timeout` (or, if it is `null`, the `DefaultTimeout` from `RegistrationCeremonyOptions` and `AuthenticationCeremonyOptions`, which is 300000 milliseconds by default) is passed to the browser as a hint that it may adjust, and it also sets the lifetime of the ceremony on the server: the ceremony and its challenge stay valid for `timeout` milliseconds after `BeginCeremonyAsync`. After that, `CompleteCeremonyAsync` returns a failed result, and the ceremony has to be started again with `BeginCeremonyAsync`. When choosing the `timeout`, keep in mind that [the specification recommends](https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges) keeping challenges valid for a duration similar to the upper limit of the [recommended range of the ceremony timeout](https://www.w3.org/TR/webauthn-3/#sctn-timeout-recommended-range) (600000 milliseconds), while a shorter lifetime narrows the window in which a captured response can be replayed.

With conditional mediation (`mediation: "conditional"`, passkey autofill), the browser [waits for the user without a time limit](https://www.w3.org/TR/webauthn-3/#sctn-discover-from-external-source). If such a page can stay open longer than the ceremony lifetime, request new options with `BeginCeremonyAsync` and restart `navigator.credentials.get()` before the ceremony expires, or pass a larger `timeout`.

After a successful `CompleteCeremonyAsync`, the ceremony is removed from the storage. The default storage keeps the ceremony in an encrypted cookie, so for it the removal is only a request to the browser to delete the cookie, and a captured cookie together with the response can be replayed until the ceremony expires. If this matters, use a server-side storage for ceremonies (implement `IRegistrationCeremonyStorage<TContext>` and `IAuthenticationCeremonyStorage<TContext>`).

## Context

To ensure the execution of each operation in a transaction (creation of registration ceremony options, completion of the registration ceremony, creation of authentication ceremony options, completion of the authentication ceremony), a context is used.

This is a class that implements the `IWebAuthnContext` interface, which in turn inherits the `IAsyncDisposable` interface, and also contains a property for accessing the current request context (`HttpContext`) and the `CommitAsync` method, which is called at the very end of each operation before returning the result.

The context is passed to all methods that work with the database, which allows different components of the library to access the same transaction throughout the entire request processing pipeline.

The context is created by calling the `IWebAuthnContextFactory.CreateAsync` method, which takes the current request context (`HttpContext`) as a parameter. It is assumed that within the `IWebAuthnContextFactory` implementation, a connection to the database will be established, and a transaction, within which the current request will be processed, will be opened.

## FIDO Metadata

To ensure trustworthiness, the service refers to the metadata in the [FIDO Metadata Service](https://fidoalliance.org/metadata) and uses its data in the process of validating requests.

WebAuthn.Net includes a background service (`FidoMetadataIngestBackgroundService`, derived from [`BackgroundService`](https://learn.microsoft.com/dotnet/core/extensions/workers)) that loads, verifies, and periodically updates these metadata. It loads them at start-up, in `StartAsync`, and then updates them in the background, in `ExecuteAsync`, until the application stops. By default, WebAuthn.Net keeps them in an in-memory storage.

### Loading and updates

1. At start-up, the blob embedded in the application is loaded first, if you have embedded one (see [Embedding the metadata in the application](#embedding-the-metadata-in-the-application)).
2. Then the blob is loaded from the FIDO Metadata Service, in any case:
    - if the embedded blob has been loaded, the start of the application doesn't wait for the FIDO Metadata Service: the blob is downloaded in the background right away;
    - otherwise, the start of the application waits for the first attempt to download the blob.
3. If an attempt fails (the blob can't be downloaded, verified or decoded, or an exception occurs), the next attempt is made after `RetryInterval` (1 minute by default), and so on until the blob is loaded. The metadata in use, if any, is kept meanwhile.
4. Once the blob is loaded, the metadata is refreshed every `IngestInterval` (1 day by default, as the FIDO Metadata Service [recommends](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-considerations) for typical applications). If a refresh fails, the attempts are made every `RetryInterval` again until the blob is loaded.

A failure never stops the background updates: it is logged and counted (see [Monitoring](#monitoring)), and the attempts go on. `ExecuteAsync` ends only when the application stops, so the host never treats the service as failed, which by default (`BackgroundServiceExceptionBehavior.StopHost`) would stop the whole application.

The intervals are set in `FidoMetadataIngestBackgroundServiceOptions`, which are configured by the `configureIngestBackgroundService` parameter of the `AddWebAuthn*` extension methods:

```csharp
services.AddWebAuthnSqlServer(
    configureIngestBackgroundService: ingest =>
    {
        ingest.RetryInterval = TimeSpan.FromMinutes(1);
        ingest.IngestInterval = TimeSpan.FromDays(1);
    },
    configureSqlServer: sqlServer =>
    {
        sqlServer.ConnectionString = "CONNECTION_STRING_HERE";
    });
```

### Embedding the metadata in the application

So that the application starts with metadata and works even if the FIDO Metadata Service is unavailable (it is down, it limits the rate of the requests, or the outbound connections of the application are restricted), embed the blob in the application.

1. Download the blob, for example, with `curl -L -o FidoMetadata/blob.jwt https://mds3.fidoalliance.org`. The retrieval and use of the blob are subject to the [legal terms of the FIDO Metadata Service](https://fidoalliance.org/metadata/metadata-legal-terms/).
2. Embed the file in an assembly of the application as a manifest resource:

    ```xml
    <ItemGroup>
      <EmbeddedResource Include="FidoMetadata/blob.jwt" LogicalName="FidoMetadata.blob.jwt" />
    </ItemGroup>
    ```

    Without `LogicalName`, the name of the resource is the root namespace of the project followed by the path of the file, with dots instead of the directory separators (for example, `MyApp.FidoMetadata.blob.jwt`).
3. Set `EmbeddedBlob` in `FidoMetadataIngestBackgroundServiceOptions` to the assembly and the name of the resource:

    ```csharp
    services.AddWebAuthnSqlServer(
        configureIngestBackgroundService: ingest =>
        {
            ingest.EmbeddedBlob = new FidoMetadataEmbeddedBlobOptions(typeof(Program).Assembly, "FidoMetadata.blob.jwt");
        },
        configureSqlServer: sqlServer =>
        {
            sqlServer.ConnectionString = "CONNECTION_STRING_HERE";
        });
    ```

    `FidoMetadataEmbeddedBlobOptions` (in the `WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataIngest` namespace, like `FidoMetadataIngestBackgroundServiceOptions`) requires both the assembly and the name of the resource and throws an exception if either of them is missing, so the embedded blob is either specified completely or not specified at all (`EmbeddedBlob` is `null` by default).

The embedded blob has to be the blob exactly as the FIDO Metadata Service serves it (a JWS). It is verified like a downloaded blob: its signature and its certificate chain up to the root certificates of the FIDO Metadata Service built into WebAuthn.Net. The only difference is that the validity period and the revocation status of the signing certificates are not checked, so that the embedded blob works regardless of the time and without the network: the blobs are signed with short-lived certificates (the certificate of the blob published in October 2026 is valid for about 200 days), so an embedded blob would otherwise stop working within months, and the revocation status can't be checked without the network. This is set by `OnValidateEmbeddedFidoMetadataBlobJwtChain` in `X509ChainValidationOptions` and doesn't affect the blobs downloaded from the FIDO Metadata Service.

- The blob from the FIDO Metadata Service replaces the embedded one as soon as it is loaded, so the embedded blob is used only until then.
- An embedded blob that is not newer than the metadata in use (for example, a persistent storage keeps the blob downloaded before the restart of the application) is not ingested.
- If the embedded blob can't be loaded (for example, the resource is not found: the warning lists the names of the resources of the assembly), the reason is logged and counted, and the metadata is loaded from the FIDO Metadata Service only, as if no blob were embedded.

The statuses of the authenticators in the embedded blob become outdated over time, and the application relies on them for as long as the FIDO Metadata Service is unavailable. Therefore, update the embedded blob regularly, for example, download it in the build pipeline of the application.

### Without metadata

> [!WARNING]
> If no blob is embedded in the application and the FIDO Metadata Service is unavailable at start-up, or the downloaded blob can't be verified, the application starts without metadata. A warning is logged, and the attempts to load the blob are made every `RetryInterval` until it is loaded.

Until the metadata is available:

- `packed` attestation statements with a certificate chain and `fido-u2f` attestation statements are rejected, because their trust anchors come only from the metadata;
- `tpm` and `android-key` attestation statements are verified against the root certificates built into WebAuthn.Net, without the authenticator statuses from the metadata;
- `none`, `apple` and `packed` self attestation don't depend on the metadata.

If the application shouldn't start without metadata, set `ThrowExceptionOnFailure` to `true` in `FidoMetadataIngestBackgroundServiceOptions`. Then the start of the application fails with an exception if no metadata could be loaded at start-up: neither the embedded blob nor the blob from the FIDO Metadata Service. The flag applies only to the start-up: the failures of the background updates never throw.

### Monitoring

The loading of the metadata is counted in the `WebAuthn.Net.FidoMetadata` meter, so you can alert on it:

- `webauthn.mds.download.failures` is incremented for a blob that can't be downloaded or verified (the `reason` tag tells why, for example `request_failed` or `chain_invalid`). While the FIDO Metadata Service is unavailable, it grows every `RetryInterval`;
- `webauthn.mds.embedded.failures` is incremented when the blob embedded in the application can't be loaded (the `reason` tag tells why, for example `resource_not_found` or `signature_invalid`);
- `webauthn.mds.ingest.exceptions` is incremented when an attempt to load a blob ends with an unexpected exception, for example, of a resilience policy of the HttpClient or of a persistent storage (the `source` tag is `embedded` or `mds`). Such an exception is also logged at the `Error` level;
- `webauthn.mds.search.no_metadata` is incremented for every lookup performed without metadata.

Besides, the service logs at the `Information` level its start and its stop, every successful load, and, before each wait, how long the wait lasts and when the next attempt is made. A failed load is logged at the `Warning` level (`Error` for an unexpected exception).

### Statuses of authenticators

An authenticator that has no entry in the metadata is handled the same way as when no metadata is available. When the metadata has an entry for the authenticator, its status reports are checked first. If they don't allow to trust the authenticator (`REVOKED`, `ATTESTATION_KEY_COMPROMISE`, `USER_KEY_REMOTE_COMPROMISE`, `USER_KEY_PHYSICAL_COMPROMISE`, `USER_VERIFICATION_BYPASS`, `UPDATE_AVAILABLE`, `RETIRED`, or no status known to WebAuthn.Net), the registration is rejected for every attestation statement format that uses the metadata: `packed` with a certificate chain, `fido-u2f`, `tpm` and `android-key`. This holds even if the attestation chains up to a root certificate built into WebAuthn.Net: the revocation of attestation certificates isn't checked through X.509 revocation lists, so the statuses in the metadata are how revoked authenticator models are recognized. Every such lookup logs a warning and increments `webauthn.mds.search.untrusted`. To change which statuses are trusted, override `CanTrustMetadata` in a class derived from `DefaultFidoMetadataSearchService<TContext>`.

For `fido-u2f` attestation statements, the authenticator model is identified by the attestation certificate only: by the AAGUID of its `id-fido-gen-ce-aaguid` extension, then by its key identifier (listed in `attestationCertificateKeyIdentifiers` of the metadata), and then by the value of its Subject Key Identifier extension. The FIDO U2F attestation signature doesn't cover the AAGUID of the authenticator data, and the client sets that AAGUID to zero for a FIDO U2F authenticator (FIDO CTAP §10.2), so it is never used to find the metadata, and a registration with a non-zero AAGUID is rejected: a warning is logged and `webauthn.reg.attestation.anomalies` is incremented.

### Custom storage

You can also implement your own storage of metadata based on a persistent storage, so that the metadata survive the restarts of the application (implement `IFidoMetadataIngestStorage` and `IFidoMetadataSearchStorage<TContext>`). Such a storage should report the serial number of the stored blob (`IFidoMetadataIngestStorage.GetCurrentBlobNoAsync`), so that an older blob never replaces it, including the embedded one. The search methods of `IFidoMetadataSearchStorage<TContext>` report why nothing was found: `NotFound` if the storage has metadata but no entry for the authenticator, or `MetadataNotAvailable` if it has no metadata at all, so that the latter is logged and counted.

## Dependency Injection

WebAuthn.Net has ready-to-use extension methods that allow easy integration with `Microsoft.Extensions.DependencyInjection`.

It is assumed that all components are registered with a `Singleton` lifetime.

Meanwhile, internal registrations of all services and components are performed through `Services.TryAddSingleton` (with the exception of options, which are registered using `Services.AddOptions`). This makes it very easy to override any service or component. You just need to register it with a Singleton lifetime BEFORE calling the WebAuthn.Net extension methods. In this case, default implementations will not be registered only for those components that you have overridden.
