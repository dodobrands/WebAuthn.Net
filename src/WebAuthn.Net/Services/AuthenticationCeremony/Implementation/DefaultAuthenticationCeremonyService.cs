using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.CreateOptions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.VerifyAssertion;
using WebAuthn.Net.Services.AuthenticationCeremony.Implementation.Models;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions.Enums;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.VerifyAssertion;
using WebAuthn.Net.Services.AuthenticationCeremony.Services.AuthenticationResponseDecoder;
using WebAuthn.Net.Services.AuthenticationCeremony.Services.PublicKeyCredentialRequestOptionsEncoder;
using WebAuthn.Net.Services.Common.AttestationObjectDecoder;
using WebAuthn.Net.Services.Common.AttestationObjectDecoder.Models;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions;
using WebAuthn.Net.Services.Common.AttestationTrustPathValidator;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models.Abstractions;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models.Enums;
using WebAuthn.Net.Services.Common.ChallengeGenerator;
using WebAuthn.Net.Services.Common.ClientDataDecoder;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Services.Cryptography.Sign;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Static;
using WebAuthn.Net.Storage.AuthenticationCeremony;
using WebAuthn.Net.Storage.AuthenticationCeremony.Models;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.Credential.Models;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Implementation;

/// <summary>
///     Default implementation of <see cref="IAuthenticationCeremonyService" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultAuthenticationCeremonyService<TContext> : IAuthenticationCeremonyService
    where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     Constructs <see cref="DefaultAuthenticationCeremonyService{TContext}" />.
    /// </summary>
    /// <param name="options">Accessor for getting the current value of global options.</param>
    /// <param name="contextFactory">Factory for creating a WebAuthn operation context.</param>
    /// <param name="rpIdProvider">Provider of the rpId value based on the <see cref="HttpContext" />.</param>
    /// <param name="rpOriginProvider">Provider of the origin value based on the <see cref="HttpContext" />.</param>
    /// <param name="challengeGenerator">Generator of challenges for WebAuthn ceremonies.</param>
    /// <param name="timeProvider">Current time provider.</param>
    /// <param name="publicKeyCredentialRequestOptionsEncoder">Encoder for transforming <see cref="PublicKeyCredentialRequestOptions" /> into a model suitable for JSON serialization.</param>
    /// <param name="credentialStorage">Credential storage. This is where the credentials are located, providing methods for storing credentials that are created during the registration ceremony, as well as methods for accessing them during the authentication ceremony.</param>
    /// <param name="ceremonyStorage">Storage for authentication ceremony data.</param>
    /// <param name="authenticationResponseDecoder">Decoder for <see cref="AuthenticationResponseJSON" /> (<a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-pkcredential">PublicKeyCredential</a>) from a model suitable for JSON serialization into a typed representation.</param>
    /// <param name="clientDataDecoder">Decoder for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-client-data">clientData</a> from JSON into a typed representation.</param>
    /// <param name="attestationObjectDecoder">Decoder for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#fig-attStructs">attestationObject</a> from binary into a typed representation.</param>
    /// <param name="authenticatorDataDecoder">Decoder for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> from binary into a typed representation.</param>
    /// <param name="attestationStatementDecoder">Decoder for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a> from CBOR into a typed representation.</param>
    /// <param name="attestationStatementVerifier">Verifier of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a>.</param>
    /// <param name="attestationTrustPathValidator"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-trust-path">Attestation trust path</a> validator. It validates that the attestation statement is trustworthy.</param>
    /// <param name="signatureVerifier">Digital signature verifier.</param>
    /// <param name="counters">Counters for authentication ceremony metrics.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultAuthenticationCeremonyService(
        IOptionsMonitor<WebAuthnOptions> options,
        IWebAuthnContextFactory<TContext> contextFactory,
        IRelyingPartyIdProvider rpIdProvider,
        IRelyingPartyOriginProvider rpOriginProvider,
        IChallengeGenerator challengeGenerator,
        ITimeProvider timeProvider,
        IPublicKeyCredentialRequestOptionsEncoder publicKeyCredentialRequestOptionsEncoder,
        ICredentialStorage<TContext> credentialStorage,
        IAuthenticationCeremonyStorage<TContext> ceremonyStorage,
        IAuthenticationResponseDecoder authenticationResponseDecoder,
        IClientDataDecoder clientDataDecoder,
        IAttestationObjectDecoder attestationObjectDecoder,
        IAuthenticatorDataDecoder authenticatorDataDecoder,
        IAttestationStatementDecoder attestationStatementDecoder,
        IAttestationStatementVerifier<TContext> attestationStatementVerifier,
        IAttestationTrustPathValidator attestationTrustPathValidator,
        IDigitalSignatureVerifier signatureVerifier,
        IAuthenticationCeremonyCounters counters,
        ILogger<DefaultAuthenticationCeremonyService<TContext>> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(contextFactory);
        ArgumentNullException.ThrowIfNull(rpIdProvider);
        ArgumentNullException.ThrowIfNull(rpOriginProvider);
        ArgumentNullException.ThrowIfNull(challengeGenerator);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(publicKeyCredentialRequestOptionsEncoder);
        ArgumentNullException.ThrowIfNull(credentialStorage);
        ArgumentNullException.ThrowIfNull(ceremonyStorage);
        ArgumentNullException.ThrowIfNull(authenticationResponseDecoder);
        ArgumentNullException.ThrowIfNull(clientDataDecoder);
        ArgumentNullException.ThrowIfNull(attestationObjectDecoder);
        ArgumentNullException.ThrowIfNull(authenticatorDataDecoder);
        ArgumentNullException.ThrowIfNull(attestationStatementDecoder);
        ArgumentNullException.ThrowIfNull(attestationStatementVerifier);
        ArgumentNullException.ThrowIfNull(attestationTrustPathValidator);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        ArgumentNullException.ThrowIfNull(counters);
        ArgumentNullException.ThrowIfNull(logger);
        Options = options;
        ContextFactory = contextFactory;
        RpIdProvider = rpIdProvider;
        RpOriginProvider = rpOriginProvider;
        ChallengeGenerator = challengeGenerator;
        TimeProvider = timeProvider;
        PublicKeyCredentialRequestOptionsEncoder = publicKeyCredentialRequestOptionsEncoder;
        CredentialStorage = credentialStorage;
        CeremonyStorage = ceremonyStorage;
        AuthenticationResponseDecoder = authenticationResponseDecoder;
        ClientDataDecoder = clientDataDecoder;
        AttestationObjectDecoder = attestationObjectDecoder;
        AuthenticatorDataDecoder = authenticatorDataDecoder;
        AttestationStatementDecoder = attestationStatementDecoder;
        AttestationStatementVerifier = attestationStatementVerifier;
        AttestationTrustPathValidator = attestationTrustPathValidator;
        SignatureVerifier = signatureVerifier;
        Counters = counters;
        Logger = logger;
    }

    /// <summary>
    ///     Accessor for getting the current value of global options.
    /// </summary>
    protected IOptionsMonitor<WebAuthnOptions> Options { get; }

    /// <summary>
    ///     Factory for creating a WebAuthn operation context.
    /// </summary>
    protected IWebAuthnContextFactory<TContext> ContextFactory { get; }

    /// <summary>
    ///     Provider of the rpId value based on the <see cref="HttpContext" />.
    /// </summary>
    protected IRelyingPartyIdProvider RpIdProvider { get; }

    /// <summary>
    ///     Provider of the origin value based on the <see cref="HttpContext" />.
    /// </summary>
    protected IRelyingPartyOriginProvider RpOriginProvider { get; }

    /// <summary>
    ///     Generator of challenges for WebAuthn ceremonies.
    /// </summary>
    protected IChallengeGenerator ChallengeGenerator { get; }

    /// <summary>
    ///     Current time provider.
    /// </summary>
    protected ITimeProvider TimeProvider { get; }

    /// <summary>
    ///     Encoder for transforming <see cref="PublicKeyCredentialRequestOptions" /> into a model suitable for JSON serialization.
    /// </summary>
    protected IPublicKeyCredentialRequestOptionsEncoder PublicKeyCredentialRequestOptionsEncoder { get; }

    /// <summary>
    ///     Credential storage. This is where the credentials are located, providing methods for storing credentials that are created during the registration ceremony, as well as methods for accessing them during the authentication ceremony.
    /// </summary>
    protected ICredentialStorage<TContext> CredentialStorage { get; }

    /// <summary>
    ///     Storage for authentication ceremony data.
    /// </summary>
    protected IAuthenticationCeremonyStorage<TContext> CeremonyStorage { get; }

    /// <summary>
    ///     Decoder for <see cref="AuthenticationResponseJSON" /> (<a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-pkcredential">PublicKeyCredential</a>) from a model suitable for JSON serialization into a typed representation.
    /// </summary>
    protected IAuthenticationResponseDecoder AuthenticationResponseDecoder { get; }

    /// <summary>
    ///     Decoder for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-client-data">clientData</a> from JSON into a typed representation.
    /// </summary>
    protected IClientDataDecoder ClientDataDecoder { get; }

    /// <summary>
    ///     Decoder for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#fig-attStructs">attestationObject</a> from binary into a typed representation.
    /// </summary>
    protected IAttestationObjectDecoder AttestationObjectDecoder { get; }

    /// <summary>
    ///     Decoder for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> from binary into a typed representation.
    /// </summary>
    protected IAuthenticatorDataDecoder AuthenticatorDataDecoder { get; }

    /// <summary>
    ///     Decoder for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a> from CBOR into a typed representation.
    /// </summary>
    protected IAttestationStatementDecoder AttestationStatementDecoder { get; }

    /// <summary>
    ///     Verifier of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a>.
    /// </summary>
    protected IAttestationStatementVerifier<TContext> AttestationStatementVerifier { get; }

    /// <summary>
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-trust-path">Attestation trust path</a> validator. It validates that the attestation statement is trustworthy.
    /// </summary>
    protected IAttestationTrustPathValidator AttestationTrustPathValidator { get; }

    /// <summary>
    ///     Digital signature verifier.
    /// </summary>
    protected IDigitalSignatureVerifier SignatureVerifier { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultAuthenticationCeremonyService<TContext>> Logger { get; }

    /// <summary>
    ///     Counters for authentication ceremony metrics.
    /// </summary>
    protected IAuthenticationCeremonyCounters Counters { get; }

    /// <inheritdoc />
    public virtual async Task<BeginAuthenticationCeremonyResult> BeginCeremonyAsync(
        HttpContext httpContext,
        BeginAuthenticationCeremonyRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        Counters.IncrementBeginCeremonyStart();
        using (Logger.CreateBeginCeremonyScope())
        await using (var context = await ContextFactory.CreateAsync(httpContext, cancellationToken))
        {
            var challenge = ChallengeGenerator.GenerateChallenge(request.ChallengeSize);
            var rpId = await RpIdProvider.GetAsync(httpContext, cancellationToken);
            PublicKeyCredentialDescriptor[]? credentialsToInclude = null;
            if (request.UserHandle is not null && request.AllowCredentials is not null)
            {
                credentialsToInclude = await GetCredentialsToIncludeAsync(
                    context,
                    rpId,
                    request.UserHandle,
                    request.AllowCredentials,
                    cancellationToken);
            }

            var defaultOrigin = await RpOriginProvider.GetAsync(httpContext, cancellationToken);
            var origins = request.Origins is not null
                ? request.Origins.AllowedOrigins
                : new[] { defaultOrigin };
            // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-validating-origin
            // A web application that does not wish to be embedded in a cross-origin iframe might require topOrigin to exactly equal origin.
            string[]? topOrigins = null;
            var allowIframe = false;
            if (request.TopOrigins is not null)
            {
                topOrigins = request.TopOrigins.AllowedOrigins;
                allowIframe = true;
            }

            var expectedRpParameters = new AuthenticationCeremonyRpParameters(rpId, origins, allowIframe, topOrigins);
            var timeout = GetTimeout(request);
            var createdAt = TimeProvider.GetRoundUtcDateTime();
            var expiresAt = GetExpiresAtUtc(createdAt, timeout);
            var options = CreatePublicKeyCredentialRequestOptions(request, timeout, rpId, challenge, credentialsToInclude);
            var outputOptions = PublicKeyCredentialRequestOptionsEncoder.Encode(options);
            var authenticationCeremonyOptions = new AuthenticationCeremonyParameters(
                request.UserHandle,
                options,
                expectedRpParameters,
                createdAt,
                expiresAt);
            var ceremonyId = await CeremonyStorage.SaveAsync(context, authenticationCeremonyOptions, cancellationToken);
            await context.CommitAsync(cancellationToken);
            var result = new BeginAuthenticationCeremonyResult(outputOptions, ceremonyId);
            Counters.IncrementBeginCeremonyEnd(true);
            return result;
        }
    }

    /// <inheritdoc />
    public virtual async Task<Result<CompleteAuthenticationCeremonyResult>> CompleteCeremonyAsync(
        HttpContext httpContext,
        CompleteAuthenticationCeremonyRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        Counters.IncrementCompleteCeremonyStart();
        using (Logger.CreateCompleteCeremonyScope(request.AuthenticationCeremonyId))
        await using (var context = await ContextFactory.CreateAsync(httpContext, cancellationToken))
        {
            var authenticationCeremonyOptions = await CeremonyStorage.FindAsync(
                context,
                request.AuthenticationCeremonyId,
                cancellationToken);
            if (authenticationCeremonyOptions is null)
            {
                Logger.AuthenticationCeremonyNotFound();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            // 1. Let options be a new PublicKeyCredentialRequestOptions structure configured to the Relying Party's needs for the ceremony.
            var options = authenticationCeremonyOptions.Options;

            // 2. Call navigator.credentials.get() and pass options as the publicKey option. Let credential be the result of the successfully resolved promise.
            // If the promise is rejected, abort the ceremony with a user-visible error, or otherwise guide the user experience as might be determinable
            // from the context available in the rejected promise. For information on different error contexts and the circumstances leading to them,
            // see §6.3.3 The authenticatorGetAssertion Operation.
            var credentialResult = AuthenticationResponseDecoder.Decode(request.Response);
            if (credentialResult.HasError)
            {
                Logger.FailedToDecodeAuthenticationResponseJson();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            var credential = credentialResult.Ok;

            // 3. Let 'response' be credential.response. If response is not an instance of AuthenticatorAssertionResponse, abort the ceremony with a user-visible error.
            var response = credential.Response;

            // 4. Let 'clientExtensionResults' be the result of calling credential.getClientExtensionResults().
            // extensions not implemented

            // 5. If options.allowCredentials is not empty, verify that credential.id identifies one of the public key credentials listed in options.allowCredentials.
            if (options.AllowCredentials is not null)
            {
                if (!options.AllowCredentials.Any(x => x.Id.AsSpan().SequenceEqual(credential.Id)))
                {
                    Logger.InvalidCredentialId();
                    Counters.IncrementCompleteCeremonyEnd(false);
                    return Result<CompleteAuthenticationCeremonyResult>.Fail();
                }
            }

            // 6. Identify the user being authenticated and let credentialRecord be the credential record for the credential:
            CredentialRecord credentialRecord;
            UserCredentialRecord userCredentialRecord;

            // 7. If the user was identified before the authentication ceremony was initiated, e.g., via a username or cookie,
            // verify that the identified user account contains a credential record whose id equals credential.rawId.
            // Let 'credentialRecord' be that credential record.
            // If response.userHandle is present, verify that it equals the user handle of the user account.

            // the user was identified before the authentication ceremony was initiated
            if (authenticationCeremonyOptions.UserHandle is not null)
            {
                // verify that the identified user account contains a credential record whose id equals credential.rawId
                var dbCredential = await CredentialStorage.FindExistingCredentialForAuthenticationAsync(
                    context,
                    authenticationCeremonyOptions.ExpectedRp.RpId,
                    authenticationCeremonyOptions.UserHandle,
                    credential.RawId,
                    cancellationToken);
                if (dbCredential is null)
                {
                    Logger.CredentialNotFound();
                    Counters.IncrementCompleteCeremonyEnd(false);
                    return Result<CompleteAuthenticationCeremonyResult>.Fail();
                }

                if (!dbCredential.ContainsCredentialThatBelongsTo(
                        authenticationCeremonyOptions.ExpectedRp.RpId,
                        authenticationCeremonyOptions.UserHandle,
                        credential.RawId))
                {
                    Logger.CredentialMismatch();
                    Counters.IncrementCompleteCeremonyEnd(false);
                    return Result<CompleteAuthenticationCeremonyResult>.Fail();
                }

                // Let 'credentialRecord' be that credential record.
                credentialRecord = dbCredential.CredentialRecord;
                userCredentialRecord = dbCredential;

                // If response.userHandle is present, verify that it equals the user handle of the user account.
                if (response.UserHandle is not null)
                {
                    if (!dbCredential.UserHandle.AsSpan().SequenceEqual(response.UserHandle.AsSpan()))
                    {
                        Logger.ResponseUserHandleMismatch();
                        Counters.IncrementCompleteCeremonyEnd(false);
                        return Result<CompleteAuthenticationCeremonyResult>.Fail();
                    }
                }
            }
            // 8. If the user was not identified before the authentication ceremony was initiated, verify that response.userHandle is present.
            // Verify that the user account identified by response.userHandle contains a credential record whose id equals credential.rawId.
            // Let 'credentialRecord' be that credential record.
            else
            {
                // verify that response.userHandle is present
                if (response.UserHandle is null)
                {
                    Logger.UserHandleNotPresentInResponse();
                    Counters.IncrementCompleteCeremonyEnd(false);
                    return Result<CompleteAuthenticationCeremonyResult>.Fail();
                }

                //  Verify that the user account identified by response.userHandle contains a credential record whose id equals credential.rawId.
                var dbCredential = await CredentialStorage.FindExistingCredentialForAuthenticationAsync(
                    context,
                    authenticationCeremonyOptions.ExpectedRp.RpId,
                    response.UserHandle,
                    credential.RawId,
                    cancellationToken);
                // (check that account and bound credential exists)
                if (dbCredential is null)
                {
                    Logger.CredentialNotFound();
                    Counters.IncrementCompleteCeremonyEnd(false);
                    return Result<CompleteAuthenticationCeremonyResult>.Fail();
                }

                if (!dbCredential.ContainsCredentialThatBelongsTo(
                        authenticationCeremonyOptions.ExpectedRp.RpId,
                        response.UserHandle,
                        credential.RawId))
                {
                    Logger.CredentialMismatch();
                    Counters.IncrementCompleteCeremonyEnd(false);
                    return Result<CompleteAuthenticationCeremonyResult>.Fail();
                }

                // Let 'credentialRecord' be that credential record.
                credentialRecord = dbCredential.CredentialRecord;
                userCredentialRecord = dbCredential;
            }

            // 9. Let 'cData', 'authData' and 'sig' denote the value of response’s 'clientDataJSON', 'authenticatorData', and 'signature' respectively.
            var authDataResult = AuthenticatorDataDecoder.Decode(response.AuthenticatorData);
            if (authDataResult.HasError)
            {
                Logger.FailedToDecodeResponseAuthenticatorData();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            var cData = response.ClientDataJson;
            var authData = authDataResult.Ok;
            var sig = response.Signature;

            // 10. Let 'JSONtext' be the result of running UTF-8 decode on the value of 'cData'.
            // ReSharper disable once InconsistentNaming
            var JSONtext = Encoding.UTF8.GetString(response.ClientDataJson);

            // 11. Let 'C', the client data claimed as used for the signature, be the result of running an implementation-specific JSON parser on 'JSONtext'.
            var clientDataResult = ClientDataDecoder.Decode(JSONtext);
            if (clientDataResult.HasError)
            {
                Logger.FailedToDecodeResponseClientDataJson();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            // ReSharper disable once InconsistentNaming
            var C = clientDataResult.Ok;

            // 12. Verify that the value of C.type is the string 'webauthn.get'.
            if (C.Type is not "webauthn.get")
            {
                Logger.IncorrectClientDataType(C.Type);
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            // 13. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
            if (!string.Equals(C.Challenge, Base64Url.Encode(options.Challenge), StringComparison.Ordinal))
            {
                Logger.ChallengeMismatch();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            // 14. Verify that the value of C.origin is an origin expected by the Relying Party. See §13.4.9 Validating the origin of a credential for guidance.
            var allowedOrigin = authenticationCeremonyOptions.ExpectedRp.Origins.FirstOrDefault(x => string.Equals(x, C.Origin, StringComparison.Ordinal));
            if (allowedOrigin is null)
            {
                Logger.InvalidOrigin(C.Origin);
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            // 15. If C.topOrigin is present:
            if (C.TopOrigin is not null)
            {
                //   1. Verify that the Relying Party expects this credential to be used within an iframe that is not same-origin with its ancestors.
                //   2. Verify that the value of C.topOrigin matches the origin of a page that the Relying Party expects to be sub-framed within. See §13.4.9 Validating the origin of a credential for guidance.
                if (authenticationCeremonyOptions.ExpectedRp.AllowIframe)
                {
                    if (!authenticationCeremonyOptions.ExpectedRp.TopOrigins.Any(x => string.Equals(x, C.TopOrigin, StringComparison.Ordinal)))
                    {
                        Logger.InvalidTopOrigin(C.TopOrigin);
                        Counters.IncrementCompleteCeremonyEnd(false);
                        return Result<CompleteAuthenticationCeremonyResult>.Fail();
                    }
                }
                else
                {
                    if (!string.Equals(allowedOrigin, C.TopOrigin, StringComparison.Ordinal))
                    {
                        Logger.InvalidTopOrigin(C.TopOrigin);
                        Counters.IncrementCompleteCeremonyEnd(false);
                        return Result<CompleteAuthenticationCeremonyResult>.Fail();
                    }
                }
            }

            // 16. Verify that the 'rpIdHash' in 'authData' is the SHA-256 hash of the RP ID expected by the Relying Party.
            var authDataRpIdHash = authData.RpIdHash;
            var expectedRpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(authenticationCeremonyOptions.ExpectedRp.RpId));
            if (!authDataRpIdHash.AsSpan().SequenceEqual(expectedRpIdHash.AsSpan()))
            {
                Logger.RpIdHashMismatch();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            var userVerificationRequired = options.UserVerification is UserVerificationRequirement.Required;
            var userPresent = (authData.Flags & AuthenticatorDataFlags.UserPresent) is AuthenticatorDataFlags.UserPresent;
            bool? uvInitialized = null;
            if (userVerificationRequired)
            {
                // 17. Verify that the UP bit of the flags in authData is set.
                if (!userPresent)
                {
                    Logger.UserPresentBitNotSet();
                    Counters.IncrementCompleteCeremonyEnd(false);
                    return Result<CompleteAuthenticationCeremonyResult>.Fail();
                }

                // 18. Determine whether user verification is required for this assertion.
                // User verification SHOULD be required if, and only if, options.userVerification is set to required.
                // If user verification was determined to be required, verify that the UV bit of the flags in authData is set.
                // Otherwise, ignore the value of the UV flag.
                uvInitialized = (authData.Flags & AuthenticatorDataFlags.UserVerified) is AuthenticatorDataFlags.UserVerified;
                if (userVerificationRequired && !uvInitialized.Value)
                {
                    Logger.UserVerificationBitNotSet();
                    Counters.IncrementCompleteCeremonyEnd(false);
                    return Result<CompleteAuthenticationCeremonyResult>.Fail();
                }
            }

            // 19. If the BE bit of the flags in authData is not set, verify that the BS bit is not set.
            // 20. If the credential backup state is used as part of Relying Party business logic or policy,
            // let 'currentBe' and 'currentBs' be the values of the BE and BS bits, respectively, of the 'flags' in 'authData'.
            var currentBe = (authData.Flags & AuthenticatorDataFlags.BackupEligibility) is AuthenticatorDataFlags.BackupEligibility;
            var currentBs = (authData.Flags & AuthenticatorDataFlags.BackupState) is AuthenticatorDataFlags.BackupState;
            if (!currentBe && currentBs)
            {
                // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-credential-backup
                // §6.1.3. Credential Backup State
                // | BE | BS | Description
                // |  0 |  0 | The credential is a single-device credential.
                // |  0 |  1 | This combination is not allowed.
                // |  1 |  0 | The credential is a multi-device credential and is not currently backed up.
                // |  1 |  1 | The credential is a multi-device credential and is currently backed up.
                Logger.InvalidBeBsFlagsCombination();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            // Compare 'currentBe' and 'currentBs' with 'credentialRecord.backupEligible' and 'credentialRecord.backupState':
            // 20.1. If credentialRecord.backupEligible is set, verify that 'currentBe' is set.

            if (credentialRecord.BackupEligible)
            {
                if (!currentBe)
                {
                    Logger.BackupEligibleBitNotSet();
                    Counters.IncrementCompleteCeremonyEnd(false);
                    return Result<CompleteAuthenticationCeremonyResult>.Fail();
                }
            }

            // 20.2. If credentialRecord.backupEligible is not set, verify that 'currentBe' is not set.
            if (!credentialRecord.BackupEligible)
            {
                if (currentBe)
                {
                    Logger.BackupEligibleBitSet();
                    Counters.IncrementCompleteCeremonyEnd(false);
                    return Result<CompleteAuthenticationCeremonyResult>.Fail();
                }
            }

            // 20.3. Apply Relying Party policy, if any.
            var recommendedActions = ComputeBackupStateRecommendedActions(currentBe, currentBs, credentialRecord.BackupState);

            // 21. Verify that the values of the client extension outputs in 'clientExtensionResults' and the authenticator extension outputs
            // in the 'extensions' in 'authData' are as expected, considering the client extension input values that were given in 'options.extensions'
            // and any specific policy of the Relying Party regarding unsolicited extensions,
            // i.e., those that were not specified as part of 'options.extensions'.
            // In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.

            // extensions not implemented

            // 22. Let 'hash' be the result of computing a hash over the 'cData' using SHA-256.
            var hash = SHA256.HashData(cData);

            // 23. Using 'credentialRecord.publicKey', verify that 'sig' is a valid signature over the binary concatenation of 'authData' and 'hash'.
            var dataToVerify = Concat(authData.Raw, hash);
            if (!credentialRecord.PublicKey.TryToCoseKey(out var credentialRecordPublicKey))
            {
                Logger.FailedToTransformCredentialPublicKey();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            if (!SignatureVerifier.IsValidCoseKeySign(credentialRecordPublicKey, dataToVerify, sig))
            {
                Logger.InvalidSignature();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            // 24. If 'authData.signCount' is nonzero or 'credentialRecord.signCount' is nonzero, then run the following sub-step:
            if (authData.SignCount is not 0 || credentialRecord.SignCount is not 0)
            {
                // If authData.signCount is
                // 24.1 greater than credentialRecord.signCount: The signature counter is valid.
                // 24.2 less than or equal to credentialRecord.signCount:
                // This is a signal that the authenticator may be cloned,
                // i.e. at least two copies of the credential private key may exist and are being used in parallel.
                // Relying Parties should incorporate this information into their risk scoring.
                // Whether the Relying Party updates 'credentialRecord.signCount' below in this case, or not, or fails the authentication ceremony or not,
                // is Relying Party-specific.
                if (authData.SignCount <= credentialRecord.SignCount)
                {
                    if (Options.CurrentValue.AuthenticationCeremony.AbortCeremonyWhenSignCountIsLessOrEqualStoredValue)
                    {
                        Logger.AbortBySignCount();
                        Counters.IncrementCompleteCeremonyEnd(false);
                        return Result<CompleteAuthenticationCeremonyResult>.Fail();
                    }
                }
            }

            // 25. If 'response.attestationObject' is present and the Relying Party wishes to verify the attestation
            // then perform CBOR decoding on attestationObject to obtain the attestation statement format 'fmt', and the attestation statement 'attStmt'.
            if (response.AttestationObject is not null)
            {
                var attestationObjectResult = AttestationObjectDecoder.Decode(response.AttestationObject);
                if (attestationObjectResult.HasError)
                {
                    Logger.AttestationObjectDecodeFailed();
                    Counters.IncrementCompleteCeremonyEnd(false);
                    return Result<CompleteAuthenticationCeremonyResult>.Fail();
                }

                var attestationObjectValid = await VerifyAttestationObjectAsync(
                    context,
                    authData,
                    credentialRecordPublicKey,
                    credentialRecord.Id,
                    attestationObjectResult.Ok,
                    hash,
                    cancellationToken);
                if (!attestationObjectValid)
                {
                    Logger.AttestationObjectVerificationFailed();
                    Counters.IncrementCompleteCeremonyEnd(false);
                    return Result<CompleteAuthenticationCeremonyResult>.Fail();
                }
            }

            // 26. Update credentialRecord with new state values:
            // - Update 'credentialRecord.signCount' to the value of 'authData.signCount'.
            // - Update 'credentialRecord.backupState' to the value of 'currentBs'.
            // - If 'credentialRecord.uvInitialized' is false, update it to the value of the UV bit in the 'flags' in 'authData'.
            // This change SHOULD require authorization by an additional authentication factor equivalent to WebAuthn user verification;
            // if not authorized, skip this step.
            // - OPTIONALLY, if 'response.attestationObject' is present, update 'credentialRecord.attestationObject' to the value of 'response.attestationObject'
            // and update 'credentialRecord.attestationClientDataJSON' to the value of 'response.clientDataJSON'.

            var credentialRecordUpdateResult = UpdateCredentialRecord(
                credentialRecord,
                authData.SignCount,
                currentBs,
                uvInitialized,
                response.AttestationObject,
                response.ClientDataJson);

            var updatedCredential = new UserCredentialRecord(
                userCredentialRecord.UserHandle,
                userCredentialRecord.RpId,
                userCredentialRecord.Description,
                credentialRecordUpdateResult.UpdatedCredentialRecord);
            var updated = await CredentialStorage.UpdateCredentialAsync(context, updatedCredential, cancellationToken);
            if (!updated)
            {
                Logger.CredentialStorageUpdateFailed();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            // 27. If all the above steps are successful, continue with the authentication ceremony as appropriate. Otherwise, fail the authentication ceremony.
            var successfulResult = new CompleteAuthenticationCeremonyResult(
                recommendedActions,
                credentialRecordUpdateResult.UserVerificationFlagMayBeUpdatedToTrue,
                updatedCredential.UserHandle);
            var result = Result<CompleteAuthenticationCeremonyResult>.Success(successfulResult);
            await context.CommitAsync(cancellationToken);
            Counters.IncrementCompleteCeremonyEnd(true);
            return result;
        }
    }

    /// <summary>
    ///     Computes the expiration date of the authentication ceremony's lifetime.
    /// </summary>
    /// <param name="createdAt">Creation date of the authentication ceremony.</param>
    /// <param name="timeout">Authentication ceremony timeout in milliseconds.</param>
    /// <returns>Expiration date of the authentication ceremony's lifetime, after which its data is expected to be deleted.</returns>
    protected virtual DateTimeOffset GetExpiresAtUtc(DateTimeOffset createdAt, uint timeout)
    {
        var expiresAtMilliseconds = createdAt.ToUnixTimeMilliseconds() + timeout;
        return DateTimeOffset.FromUnixTimeMilliseconds(expiresAtMilliseconds);
    }

    /// <summary>
    ///     Computes the authentication ceremony timeout in milliseconds.
    /// </summary>
    /// <param name="request">A request containing the parameters for generating options for the authentication ceremony.</param>
    /// <returns>Authentication ceremony timeout in milliseconds.</returns>
    protected virtual uint GetTimeout(BeginAuthenticationCeremonyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Timeout.HasValue)
        {
            return request.Timeout.Value;
        }

        return Options.CurrentValue.AuthenticationCeremony.DefaultTimeout;
    }

    /// <summary>
    ///     Updates the <see cref="CredentialRecord" />.
    /// </summary>
    /// <param name="old">The CredentialRecord value that needs to be updated. </param>
    /// <param name="authDataSignCount">The updated <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-data">authData</a>.<a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-signcount">signCount</a> value.</param>
    /// <param name="currentBs">Updated value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-bs">backup state (BS)</a> flag. </param>
    /// <param name="uvInitialized">
    ///     Updated value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-uv">user verified (UV)</a> flag. Will be non-null only if
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a> is <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-userverificationrequirement-required">required</a> for the authentication ceremony.
    /// </param>
    /// <param name="responseAttestationObject">The raw value of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-object">attestationObject</a> obtained during the authentication ceremony.</param>
    /// <param name="responseClientDataJson">The raw value of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorresponse-clientdatajson">clientDataJSON</a> obtained during the authentication ceremony.</param>
    /// <returns>The result of updating the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">credentialRecord</a>.</returns>
    protected virtual CredentialRecordUpdateResult UpdateCredentialRecord(
        CredentialRecord old,
        uint authDataSignCount,
        bool currentBs,
        bool? uvInitialized,
        byte[]? responseAttestationObject,
        byte[]? responseClientDataJson)
    {
        ArgumentNullException.ThrowIfNull(old);
        var attestationObject = old.AttestationObject;
        var attestationClientDataJson = old.AttestationClientDataJSON;

        if (responseAttestationObject is not null && responseClientDataJson is not null)
        {
            attestationObject = responseAttestationObject;
            attestationClientDataJson = responseClientDataJson;
        }

        var userVerificationFlagMayBeUpdatedToTrue = !old.UvInitialized && uvInitialized.HasValue && uvInitialized.Value;

        var updatedCredentialRecord = new CredentialRecord(
            old.Type,
            old.Id,
            old.PublicKey,
            authDataSignCount,
            old.Transports,
            old.UvInitialized,
            old.BackupEligible,
            currentBs,
            attestationObject,
            attestationClientDataJson);
        return new(updatedCredentialRecord, userVerificationFlagMayBeUpdatedToTrue);
    }

    /// <summary>
    ///     Verifies the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-object">attestationObject</a> obtained during the authentication ceremony.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="abstractAuthData">Decoded typed representation of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a>.</param>
    /// <param name="credentialRecordPublicKey">The public key stored in the CredentialRecord, which is used in the authentication ceremony.</param>
    /// <param name="credentialRecordId">
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id">Credential ID</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a>, stored in the
    ///     <see cref="CredentialRecord" />, which is used in the authentication ceremony.
    /// </param>
    /// <param name="attestationObject">Decoded typed representation of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-object">attestationObject</a>.</param>
    /// <param name="hash">SHA256 hash of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorresponse-clientdatajson">clientDataJSON</a>.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns><see langword="true" /> if the verification was successful, otherwise - <see langword="false" />.</returns>
    protected virtual async Task<bool> VerifyAttestationObjectAsync(
        TContext context,
        AbstractAuthenticatorData abstractAuthData,
        AbstractCoseKey credentialRecordPublicKey,
        byte[] credentialRecordId,
        AttestationObject attestationObject,
        byte[] hash,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(abstractAuthData);
        ArgumentNullException.ThrowIfNull(attestationObject);
        // 1. Verify that the AT bit in the flags field of authData is set, indicating that attested credential data is included.
        var atBitSet = (abstractAuthData.Flags & AuthenticatorDataFlags.AttestedCredentialData) is AuthenticatorDataFlags.AttestedCredentialData;
        if (!atBitSet)
        {
            return false;
        }

        if (abstractAuthData is not AttestedAuthenticatorData authData)
        {
            return false;
        }

        // 2. Verify that the 'credentialPublicKey' and 'credentialId' fields of the attested credential data in 'authData'
        // match 'credentialRecord.publicKey' and 'credentialRecord.id', respectively.
        if (!authData.AttestedCredentialData.CredentialPublicKey.Matches(credentialRecordPublicKey))
        {
            return false;
        }

        if (!authData.AttestedCredentialData.CredentialId.AsSpan().SequenceEqual(credentialRecordId.AsSpan()))
        {
            return false;
        }

        // 3. Determine the attestation statement format by performing a USASCII case-sensitive match on 'fmt'
        // against the set of supported WebAuthn Attestation Statement Format Identifier values.
        // An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained
        // in the IANA "WebAuthn Attestation Statement Format Identifiers" registry [IANA-WebAuthn-Registries] established by [RFC8809].
        var fmt = attestationObject.Fmt;
        var attStmtResult = AttestationStatementDecoder.Decode(attestationObject.AttStmt, fmt);
        if (attStmtResult.HasError)
        {
            return false;
        }


        var attStmt = attStmtResult.Ok;

        // 4. Verify that 'attStmt' is a correct attestation statement, conveying a valid attestation signature,
        // by using the attestation statement format fmt’s verification procedure given 'attStmt', 'authData' and 'hash'.
        var attStmtVerificationResult = await AttestationStatementVerifier.VerifyAttestationStatementAsync(
            context,
            fmt,
            attStmt,
            authData,
            hash,
            cancellationToken);
        if (attStmtVerificationResult.HasError)
        {
            return false;
        }

        var attStmtVerification = attStmtVerificationResult.Ok;

        // 5. If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates)
        // for that attestation type and attestation statement format 'fmt', from a trusted source or from policy.
        // The 'aaguid' in the attested credential data can be used to guide this lookup.
        if (!AttestationTrustPathValidator.IsValid(attStmtVerification))
        {
            return false;
        }

        return true;
    }


    /// <summary>
    ///     Concatenates two ReadOnlySpan of bytes into one array.
    /// </summary>
    /// <param name="a">First ReadOnlySpan of bytes.</param>
    /// <param name="b">Second ReadOnlySpan of bytes.</param>
    /// <returns>An array of bytes, filled with the content of the passed ReadOnlySpans.</returns>
    protected virtual byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }

    /// <summary>
    ///     Computes the recommended actions that need to be taken after the authentication ceremony based on <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-credential-backup">credential backup state</a>.
    /// </summary>
    /// <param name="currentBe">The value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-be">backup eligibility (BE)</a> flag for the credential obtained in the current authentication ceremony.</param>
    /// <param name="currentBs">The value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-bs">backup state (BS)</a> flag for the credential obtained in the current authentication ceremony.</param>
    /// <param name="credentialRecordBackupState">The previous value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-be">backup eligibility (BE)</a> flag, which was previously saved for the credential used in the authentication ceremony.</param>
    /// <returns>An array of recommended actions to be performed after the authentication ceremony based on the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-credential-backup">credential backup state</a>. Can be an empty array, cannot be <see langword="null" />.</returns>
    protected virtual CredentialBackupStateRecommendedAction[] ComputeBackupStateRecommendedActions(
        bool currentBe,
        bool currentBs,
        bool credentialRecordBackupState)
    {
        var result = new HashSet<CredentialBackupStateRecommendedAction>();

        // When the BE flag is set to 0
        if (!currentBe)
        {
            result.Add(CredentialBackupStateRecommendedAction.RequiringAdditionalAuthenticators);
        }

        // When the BS flag changes from 0 to 1,
        if (!credentialRecordBackupState)
        {
            if (currentBs)
            {
                result.Add(CredentialBackupStateRecommendedAction.UpgradingUserToPasswordlessAccount);
            }
        }

        // When the BS flag changes from 1 to 0
        if (credentialRecordBackupState)
        {
            if (!currentBs)
            {
                result.Add(CredentialBackupStateRecommendedAction.AddingAdditionalFactorAfterStateChange);
            }
        }

        return result.ToArray();
    }

    /// <summary>
    ///     Returns the descriptors of credentials that will be included in the resulting set of <see cref="PublicKeyCredentialRequestOptions.AllowCredentials" /> options of the authentication ceremony.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="rpId">The rpId for which the descriptor set is being formed.</param>
    /// <param name="userHandle">The unique identifier of the user for whom the descriptor set is being formed.</param>
    /// <param name="options">The parameters for forming the descriptor set, obtained from the request to create authentication ceremony options.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>An array containing at least one descriptor or <see langword="null" />.</returns>
    protected virtual async Task<PublicKeyCredentialDescriptor[]?> GetCredentialsToIncludeAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        AuthenticationCeremonyIncludeCredentials options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        if (options.IncludeAllExistingKeys)
        {
            var existingKeys = await CredentialStorage.FindDescriptorsAsync(context, rpId, userHandle, cancellationToken);
            if (existingKeys.Length > 0)
            {
                return existingKeys;
            }

            return null;
        }

        if (options.IncludeManuallySpecified)
        {
            var existingKeys = await CredentialStorage.FindDescriptorsAsync(context, rpId, userHandle, cancellationToken);
            if ((existingKeys.Length > 0) is not true)
            {
                return null;
            }

            var resultKeysToInclude = new List<PublicKeyCredentialDescriptor>(options.ManuallySpecifiedKeysToInclude.Length);
            foreach (var manualKey in options.ManuallySpecifiedKeysToInclude)
            {
                var existingKey = existingKeys.FirstOrDefault(x =>
                    x.Type == manualKey.Type
                    && x.Id.AsSpan().SequenceEqual(manualKey.Id));
                if (existingKey is not null)
                {
                    resultKeysToInclude.Add(existingKey);
                }
            }

            if (resultKeysToInclude.Count > 0)
            {
                return resultKeysToInclude.ToArray();
            }
        }

        return null;
    }

    /// <summary>
    ///     Creates options with which the authentication ceremony will be performed.
    /// </summary>
    /// <param name="request">A request containing the parameters for generating options for the authentication ceremony.</param>
    /// <param name="timeout">Authentication ceremony timeout in milliseconds.</param>
    /// <param name="rpId">The rpId on which the authentication ceremony will be performed.</param>
    /// <param name="challenge">The challenge that will be used in the authentication ceremony.</param>
    /// <param name="allowCredentials">
    ///     An array of public key descriptors for the authentication ceremony. If <see langword="null" />, then only <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credentials</a> will be utilized in this
    ///     authentication ceremony.
    /// </param>
    /// <returns>Options with which the authentication ceremony will be performed.</returns>
    protected virtual PublicKeyCredentialRequestOptions CreatePublicKeyCredentialRequestOptions(
        BeginAuthenticationCeremonyRequest request,
        uint timeout,
        string rpId,
        byte[] challenge,
        PublicKeyCredentialDescriptor[]? allowCredentials)
    {
        ArgumentNullException.ThrowIfNull(request);
        var options = new PublicKeyCredentialRequestOptions(
            challenge,
            timeout,
            rpId,
            allowCredentials,
            request.UserVerification,
            request.Hints,
            request.Attestation,
            request.AttestationFormats,
            request.Extensions);
        return options;
    }
}

/// <summary>
///     Extension methods for logging the authentication ceremony.
/// </summary>
public static partial class DefaultAuthenticationCeremonyServiceLoggingExtensions
{
    private static readonly Func<ILogger, IDisposable?> CreateBeginCeremonyScopeDelegate = LoggerMessage.DefineScope(
        "Authentication ceremony start");

    private static readonly Func<ILogger, string, IDisposable?> CreateCompleteCeremonyScopeDelegate = LoggerMessage.DefineScope<string>(
        "Completion of the authentication ceremony: {AuthenticationCeremonyId}");

    /// <summary>
    ///     Creates a logging scope, within which the start of the authentication ceremony will be handled.
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <returns>A logging scope, in the form of an IDisposable object, the Dispose of which signifies the end of the scope's operation.</returns>
    public static IDisposable? CreateBeginCeremonyScope(
        this ILogger logger)
    {
        return CreateBeginCeremonyScopeDelegate(logger);
    }

    /// <summary>
    ///     Creates a logging scope, within which the completion of the authentication ceremony will be handled.
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="authenticationCeremonyId">The identifier of the authentication ceremony, for which the completion of the ceremony will be processed.</param>
    /// <returns>A logging scope, in the form of an IDisposable object, the Dispose of which signifies the end of the scope's operation.</returns>
    public static IDisposable? CreateCompleteCeremonyScope(
        this ILogger logger,
        string authenticationCeremonyId)
    {
        return CreateCompleteCeremonyScopeDelegate(logger, authenticationCeremonyId);
    }

    /// <summary>
    ///     Authentication ceremony not found.
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Authentication ceremony not found")]
    public static partial void AuthenticationCeremonyNotFound(this ILogger logger);

    /// <summary>
    ///     Failed to decode AuthenticationResponseJSON
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode AuthenticationResponseJSON")]
    public static partial void FailedToDecodeAuthenticationResponseJson(this ILogger logger);

    /// <summary>
    ///     The received credential.id is not included in the list specified in options.allowCredentials
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The received credential.id is not included in the list specified in options.allowCredentials")]
    public static partial void InvalidCredentialId(this ILogger logger);

    /// <summary>
    ///     Failed to find an existing credential with the specified Id
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find an existing credential with the specified Id")]
    public static partial void CredentialNotFound(this ILogger logger);

    /// <summary>
    ///     The credential obtained from the storage does not match the parameters of the authentication ceremony
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The credential obtained from the storage does not match the parameters of the authentication ceremony")]
    public static partial void CredentialMismatch(this ILogger logger);

    /// <summary>
    ///     response.userHandle does not equal the user handle of the user account
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "response.userHandle does not equal the user handle of the user account")]
    public static partial void ResponseUserHandleMismatch(this ILogger logger);

    /// <summary>
    ///     response.userHandle is not present
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "response.userHandle is not present")]
    public static partial void UserHandleNotPresentInResponse(this ILogger logger);

    /// <summary>
    ///     Failed to decode response.AuthenticatorData
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode response.AuthenticatorData")]
    public static partial void FailedToDecodeResponseAuthenticatorData(this ILogger logger);

    /// <summary>
    ///     Failed to decode response.clientDataJSON
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode response.clientDataJSON")]
    public static partial void FailedToDecodeResponseClientDataJson(this ILogger logger);

    /// <summary>
    ///     The 'clientData.type' is incorrect, as it expected 'webauthn.get' but received '{ClientDataType}'
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="clientDataType">The received 'clientData.type' value.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'clientData.type' is incorrect, as it expected 'webauthn.get' but received '{ClientDataType}'")]
    public static partial void IncorrectClientDataType(this ILogger logger, string clientDataType);

    /// <summary>
    ///     The challenge in the authentication completion request doesn't match the one generated for this authentication ceremony
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The challenge in the authentication completion request doesn't match the one generated for this authentication ceremony")]
    public static partial void ChallengeMismatch(this ILogger logger);

    /// <summary>
    ///     Invalid value for origin: '{ClientDataOrigin}'
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="clientDataOrigin">The origin obtained from clientData.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Invalid value for origin: '{ClientDataOrigin}'")]
    public static partial void InvalidOrigin(this ILogger logger, string clientDataOrigin);

    /// <summary>
    ///     Invalid value for topOrigin: '{ClientDataTopOrigin}'
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="clientDataTopOrigin">The topOrigin obtained from clientData.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Invalid value for topOrigin: '{ClientDataTopOrigin}'")]
    public static partial void InvalidTopOrigin(this ILogger logger, string clientDataTopOrigin);

    /// <summary>
    ///     The 'rpIdHash' in 'authData' does not match the SHA-256 hash of the RP ID expected by the Relying Party
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'rpIdHash' in 'authData' does not match the SHA-256 hash of the RP ID expected by the Relying Party")]
    public static partial void RpIdHashMismatch(this ILogger logger);

    /// <summary>
    ///     User Present bit in 'authData.flags' isn't set
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "User Present bit in 'authData.flags' isn't set")]
    public static partial void UserPresentBitNotSet(this ILogger logger);

    /// <summary>
    ///     User Verification bit in 'authData.flags' is required, but not set
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "User Verification bit in 'authData.flags' is required, but not set")]
    public static partial void UserVerificationBitNotSet(this ILogger logger);

    /// <summary>
    ///     'authData.flags' contains an invalid combination of Backup Eligibility (BE) and Backup State (BS) flags
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'authData.flags' contains an invalid combination of Backup Eligibility (BE) and Backup State (BS) flags")]
    public static partial void InvalidBeBsFlagsCombination(this ILogger logger);

    /// <summary>
    ///     Backup Eligible bit in 'authData.flags' is required, but not set
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Backup Eligible bit in 'authData.flags' is required, but not set")]
    public static partial void BackupEligibleBitNotSet(this ILogger logger);

    /// <summary>
    ///     Backup Eligible bit in 'authData.flags' is set, but it shouldn't be
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Backup Eligible bit in 'authData.flags' is set, but it shouldn't be")]
    public static partial void BackupEligibleBitSet(this ILogger logger);

    /// <summary>
    ///     Failed to transform the public key of the found credentialRecord into a CoseKey
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to transform the public key of the found credentialRecord into a CoseKey")]
    public static partial void FailedToTransformCredentialPublicKey(this ILogger logger);

    /// <summary>
    ///     Invalid signature
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Invalid signature")]
    public static partial void InvalidSignature(this ILogger logger);

    /// <summary>
    ///     The obtained signCount is less than or equal to the one that was saved earlier
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The obtained signCount is less than or equal to the one that was saved earlier")]
    public static partial void AbortBySignCount(this ILogger logger);

    /// <summary>
    ///     Failed to perform CBOR decoding of the AttestationObject
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to perform CBOR decoding of the AttestationObject")]
    public static partial void AttestationObjectDecodeFailed(this ILogger logger);

    /// <summary>
    ///     AttestationObject is invalid
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "AttestationObject is invalid")]
    public static partial void AttestationObjectVerificationFailed(this ILogger logger);

    /// <summary>
    ///     Failed to update user credential record
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to update user credential record")]
    public static partial void CredentialStorageUpdateFailed(this ILogger logger);
}
