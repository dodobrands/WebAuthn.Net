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
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models.Abstractions;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models.Enums;
using WebAuthn.Net.Services.Common.ChallengeGenerator;
using WebAuthn.Net.Services.Common.ClientDataDecoder;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Services.Cryptography.Sign;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Providers;
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
    /// <param name="authenticationResponseDecoder">Decoder for <see cref="AuthenticationResponseJSON" /> (<a href="https://www.w3.org/TR/webauthn-3/#iface-pkcredential">PublicKeyCredential</a>) from a model suitable for JSON serialization into a typed representation.</param>
    /// <param name="clientDataDecoder">Decoder for <a href="https://www.w3.org/TR/webauthn-3/#dictionary-client-data">clientData</a> from JSON into a typed representation.</param>
    /// <param name="authenticatorDataDecoder">Decoder for <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> from binary into a typed representation.</param>
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
        IAuthenticatorDataDecoder authenticatorDataDecoder,
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
        ArgumentNullException.ThrowIfNull(authenticatorDataDecoder);
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
        AuthenticatorDataDecoder = authenticatorDataDecoder;
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
    ///     Decoder for <see cref="AuthenticationResponseJSON" /> (<a href="https://www.w3.org/TR/webauthn-3/#iface-pkcredential">PublicKeyCredential</a>) from a model suitable for JSON serialization into a typed representation.
    /// </summary>
    protected IAuthenticationResponseDecoder AuthenticationResponseDecoder { get; }

    /// <summary>
    ///     Decoder for <a href="https://www.w3.org/TR/webauthn-3/#dictionary-client-data">clientData</a> from JSON into a typed representation.
    /// </summary>
    protected IClientDataDecoder ClientDataDecoder { get; }

    /// <summary>
    ///     Decoder for <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> from binary into a typed representation.
    /// </summary>
    protected IAuthenticatorDataDecoder AuthenticatorDataDecoder { get; }

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
            // https://www.w3.org/TR/webauthn-3/#sctn-validating-origin
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

            // https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges
            // The challenge is valid only for the lifetime of the ceremony.
            // Otherwise a captured response could be replayed for as long as the ceremony data can be read.
            if (IsCeremonyExpired(authenticationCeremonyOptions))
            {
                Logger.AuthenticationCeremonyExpired();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            // https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion
            // In order to perform an authentication ceremony, the Relying Party MUST proceed as follows:

            // 1. Let 'options' be a 'new CredentialRequestOptions' structure configured to the Relying Party’s needs for the ceremony.
            // Let 'pkOptions' be 'options.publicKey'.
            var pkOptions = authenticationCeremonyOptions.Options;

            // 2. Call 'navigator.credentials.get()' and pass 'options' as the argument.
            // Let 'credential' be the result of the successfully resolved promise.
            // If the promise is rejected, abort the ceremony with a user-visible error,
            // or otherwise guide the user experience as might be determinable from the context available in the rejected promise.
            // For information on different error contexts and the circumstances leading to them,
            // see "The authenticatorGetAssertion Operation" (https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion).

            // 3. Let 'response' be 'credential.response'.
            // If 'response' is not an instance of 'AuthenticatorAssertionResponse',
            // abort the ceremony with a user-visible error.
            var credentialResult = AuthenticationResponseDecoder.Decode(request.Response);
            if (credentialResult.HasError)
            {
                Logger.FailedToDecodeAuthenticationResponseJson();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            var credential = credentialResult.Ok;

            // https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-rawid
            // 'credential.id' is the base64url encoding of 'credential.rawId', both represent the same credential ID.
            // Step 5 checks 'credential.id' and step 6 looks up 'credential.rawId', so the client must not be able to make them differ.
            if (!credential.Id.AsSpan().SequenceEqual(credential.RawId))
            {
                Logger.CredentialIdDoesNotMatchRawId();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            var response = credential.Response;
            // 4. Let 'clientExtensionResults' be the result of calling 'credential.getClientExtensionResults()'.
            // -- extensions NOT implemented. User may override current method to uport them.

            // 5. If 'pkOptions.allowCredentials' is not empty,
            // verify that 'credential.id' identifies one of the public key credentials
            // listed in 'pkOptions.allowCredentials'.
            if (pkOptions.AllowCredentials is not null)
            {
                if (!pkOptions.AllowCredentials.Any(x => x.Id.AsSpan().SequenceEqual(credential.Id)))
                {
                    Logger.InvalidCredentialId();
                    Counters.IncrementCompleteCeremonyEnd(false);
                    return Result<CompleteAuthenticationCeremonyResult>.Fail();
                }
            }

            // 6. Identify the user being authenticated
            // and let 'credentialRecord' be the credential record for the credential:
            CredentialRecord credentialRecord;
            UserCredentialRecord userCredentialRecord;

            // (6.1) If the user was identified before the authentication ceremony was initiated, e.g., via a username or cookie,
            // verify that the identified user account contains a credential record whose 'id' equals 'credential.rawId'.
            // Let 'credentialRecord' be that credential record.
            // If 'response.userHandle' is present, verify that it equals the user handle of the user account.

            // the user was identified before the authentication ceremony was initiated
            if (authenticationCeremonyOptions.UserHandle is not null)
            {
                // verify that the identified user account contains a credential record whose 'id' equals 'credential.rawId'
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

                // Let 'credentialRecord' be that credential record
                credentialRecord = dbCredential.CredentialRecord;
                userCredentialRecord = dbCredential;

                // If 'response.userHandle' is present, verify that it equals the user handle of the user account
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
            // (6.2) If the user was not identified before the authentication ceremony was initiated,
            // verify that 'response.userHandle' is present.
            // Verify that the user account identified by 'response.userHandle' contains a credential record whose 'id' equals 'credential.rawId'.
            // Let 'credentialRecord' be that credential record.
            else
            {
                // verify that 'response.userHandle' is present
                if (response.UserHandle is null)
                {
                    Logger.UserHandleNotPresentInResponse();
                    Counters.IncrementCompleteCeremonyEnd(false);
                    return Result<CompleteAuthenticationCeremonyResult>.Fail();
                }

                //  Verify that the user account identified by 'response.userHandle' contains a credential record whose 'id' equals 'credential.rawId'
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

                // Let 'credentialRecord' be that credential record
                credentialRecord = dbCredential.CredentialRecord;
                userCredentialRecord = dbCredential;
            }

            // 7. Let 'cData', 'authData' and 'sig' denote the value of response’s 'clientDataJSON', 'authenticatorData', and 'signature' respectively.
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

            // 8. Let 'JSONtext' be the result of running UTF-8 decode on the value of 'cData'.
            // ReSharper disable once InconsistentNaming
            var JSONtext = Encoding.UTF8.GetString(cData);

            // 11. Let 'C', the client data claimed as used for the signature, be the result of running an implementation-specific JSON parser on 'JSONtext'
            var clientDataResult = ClientDataDecoder.Decode(JSONtext);
            if (clientDataResult.HasError)
            {
                Logger.FailedToDecodeResponseClientDataJson();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            // ReSharper disable once InconsistentNaming
            var C = clientDataResult.Ok;

            // 10. Verify that the value of 'C.type' is the string 'webauthn.get'
            if (C.Type is not "webauthn.get")
            {
                Logger.IncorrectClientDataType(LogValue.Sanitize(C.Type));
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            // 11. Verify that the value of 'C.challenge' equals the base64url encoding of 'pkOptions.challenge'.
            if (!string.Equals(C.Challenge, Base64Url.Encode(pkOptions.Challenge), StringComparison.Ordinal))
            {
                Logger.ChallengeMismatch();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            // 12. Verify that the value of 'C.origin' is an origin expected by the Relying Party.
            // See "Validating the origin of a credential" (https://www.w3.org/TR/webauthn-3/#sctn-validating-origin) for guidance.
            var allowedOrigin = authenticationCeremonyOptions.ExpectedRp.Origins.FirstOrDefault(x => string.Equals(x, C.Origin, StringComparison.Ordinal));
            if (allowedOrigin is null)
            {
                Logger.InvalidOrigin(LogValue.Sanitize(C.Origin));
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            // 13. If 'C.crossOrigin' is present and set to 'true',
            // verify that the Relying Party expects this credential to be used within an iframe
            // that is not same-origin with its ancestors.
            // ('C.topOrigin' was added in Level 3, so a client may send 'crossOrigin' without 'topOrigin'.)
            if (C.CrossOrigin is true && C.TopOrigin is null && !authenticationCeremonyOptions.ExpectedRp.AllowIframe)
            {
                Logger.UnexpectedCrossOrigin();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            // 14. If 'C.topOrigin' is present:
            if (C.TopOrigin is not null)
            {
                //   14.1 Verify that the Relying Party expects this credential to be used within an iframe
                //        that is not same-origin with its ancestors.
                //   14.2 Verify that the value of 'C.topOrigin' matches the origin of a page
                //        that the Relying Party expects to be sub-framed within.
                //        See "Validating the origin of a credential" (https://www.w3.org/TR/webauthn-3/#sctn-validating-origin) for guidance.
                if (authenticationCeremonyOptions.ExpectedRp.AllowIframe)
                {
                    if (!authenticationCeremonyOptions.ExpectedRp.TopOrigins.Any(x => string.Equals(x, C.TopOrigin, StringComparison.Ordinal)))
                    {
                        Logger.InvalidTopOrigin(LogValue.Sanitize(C.TopOrigin));
                        Counters.IncrementCompleteCeremonyEnd(false);
                        return Result<CompleteAuthenticationCeremonyResult>.Fail();
                    }
                }
                else
                {
                    // A web application that does not wish to be embedded in a cross-origin iframe might require topOrigin to exactly equal origin.
                    if (!string.Equals(allowedOrigin, C.TopOrigin, StringComparison.Ordinal))
                    {
                        Logger.InvalidTopOrigin(LogValue.Sanitize(C.TopOrigin));
                        Counters.IncrementCompleteCeremonyEnd(false);
                        return Result<CompleteAuthenticationCeremonyResult>.Fail();
                    }
                }
            }

            // 15. Verify that the 'rpIdHash' in 'authData' is the SHA-256 hash of the RP ID expected by the Relying Party
            var authDataRpIdHash = authData.RpIdHash;
            var expectedRpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(authenticationCeremonyOptions.ExpectedRp.RpId));
            if (!authDataRpIdHash.AsSpan().SequenceEqual(expectedRpIdHash.AsSpan()))
            {
                Logger.RpIdHashMismatch();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            // 16. Verify that the 'UP' bit of the 'flags' in 'authData' is set.
            var up = (authData.Flags & AuthenticatorDataFlags.UserPresent) is AuthenticatorDataFlags.UserPresent;
            if (!up)
            {
                Logger.UserPresentBitNotSet();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            // 17. Determine whether user verification is required for this assertion.
            // User verification SHOULD be 'required' if, and only if,
            // 'pkOptions.userVerification' is set to 'required'.
            if (pkOptions.UserVerification == UserVerificationRequirement.Required)
            {
                // If user verification was determined to be required,
                // verify that the 'UV' bit of the 'flags' in 'authData' is set.
                // Otherwise, ignore the value of the 'UV' flag.
                var uv = (authData.Flags & AuthenticatorDataFlags.UserVerified) is AuthenticatorDataFlags.UserVerified;
                if (!uv)
                {
                    Logger.UserVerificationBitNotSet();
                    Counters.IncrementCompleteCeremonyEnd(false);
                    return Result<CompleteAuthenticationCeremonyResult>.Fail();
                }
            }

            // 18. If the 'BE' bit of the 'flags' in 'authData' is not set, verify that the 'BS' bit is not set.
            // 19. If the credential backup state is used as part of Relying Party business logic or policy,
            // let 'currentBe' and 'currentBs' be the values of the 'BE' and 'BS' bits, respectively,
            // of the 'flags' in 'authData'.
            // Compare 'currentBe' and 'currentBs' with 'credentialRecord.backupEligible'
            // and 'credentialRecord.backupState':
            // 19.1 If 'credentialRecord.backupEligible' is set, verify that 'currentBe' is set.
            // 19.2 If 'credentialRecord.backupEligible' is not set, verify that 'currentBe' is not set.
            // 19.3 Apply Relying Party policy, if any.
            // See "Credential Backup State" (https://www.w3.org/TR/webauthn-3/#sctn-credential-backup)
            // for examples of how a Relying Party might process the BS flag values.
            var currentBe = (authData.Flags & AuthenticatorDataFlags.BackupEligibility) is AuthenticatorDataFlags.BackupEligibility;
            var currentBs = (authData.Flags & AuthenticatorDataFlags.BackupState) is AuthenticatorDataFlags.BackupState;
            if (!currentBe && currentBs)
            {
                // https://www.w3.org/TR/webauthn-3/#sctn-credential-backup
                // "Credential Backup State"
                // | BE | BS | Description
                // |  0 |  0 | The credential is a single-device credential.
                // |  0 |  1 | This combination is not allowed.
                // |  1 |  0 | The credential is a multi-device credential and is not currently backed up.
                // |  1 |  1 | The credential is a multi-device credential and is currently backed up.
                Logger.InvalidBeBsFlagsCombination();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteAuthenticationCeremonyResult>.Fail();
            }

            if (credentialRecord.BackupEligible)
            {
                if (!currentBe)
                {
                    Logger.BackupEligibleBitNotSet();
                    Counters.IncrementCompleteCeremonyEnd(false);
                    return Result<CompleteAuthenticationCeremonyResult>.Fail();
                }
            }

            if (!credentialRecord.BackupEligible)
            {
                if (currentBe)
                {
                    Logger.BackupEligibleBitSet();
                    Counters.IncrementCompleteCeremonyEnd(false);
                    return Result<CompleteAuthenticationCeremonyResult>.Fail();
                }
            }

            var recommendedActions = ComputeBackupStateRecommendedActions(currentBe, currentBs, credentialRecord.BackupState);

            // 20. Let 'hash' be the result of computing a hash over the 'cData' using SHA-256.
            var hash = SHA256.HashData(cData);

            // 21. Using 'credentialRecord.publicKey', verify that 'sig' is a valid signature
            // over the binary concatenation of 'authData' and 'hash'.
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

            // 22. If 'authData.signCount' is nonzero or 'credentialRecord.signCount' is nonzero,
            // then run the following sub-step:
            // 22.1 If 'authData.signCount' is greater than 'credentialRecord.signCount':
            //      The signature counter is valid.
            // 22.2 If 'authData.signCount' is less than or equal to 'credentialRecord.signCount':
            //      This is a signal, but not proof, that the authenticator may be cloned.
            //      For example it might mean that:
            //      - Two or more copies of the credential private key may exist and are being used in parallel.
            //      - An authenticator is malfunctioning.
            //      - A race condition exists where the Relying Party is processing assertion responses in an order other than the order they were generated at the authenticator.
            //      Relying Parties should evaluate their own operational characteristics
            //      and incorporate this information i into their risk scoring.
            //      Whether the Relying Party updates 'credentialRecord.signCount' below in this case,
            //      or not, or fails the authentication ceremony or not, is Relying Party-specific.
            //      For more information on signature counter considerations,
            //      see "Signature Counter Considerations" (https://www.w3.org/TR/webauthn-3/#sctn-sign-counter).
            if (authData.SignCount is not 0 || credentialRecord.SignCount is not 0)
            {
                if (authData.SignCount <= credentialRecord.SignCount)
                {
                    if (Options.CurrentValue.AuthenticationCeremony.AbortCeremonyWhenSignCountIsLessOrEqualStoredValue)
                    {
                        Logger.AbortBySignCount();
                        Counters.IncrementCompleteCeremonyEnd(false);
                        return Result<CompleteAuthenticationCeremonyResult>.Fail();
                    }

                    // The ceremony continues by Relying Party policy, but the signal of a possibly cloned authenticator must stay visible.
                    Logger.SignCountNotIncreased(authData.SignCount, credentialRecord.SignCount);
                }
            }

            // 23. Process the client extension outputs in 'clientExtensionResults'
            // and the authenticator extension outputs in the extensions in 'authData'
            // as required by the Relying Party.
            // Depending on each extension, processing steps may be concretely specified or it
            // may be up to the Relying Party what to do with extension outputs.
            // The Relying Party MAY ignore any or all extension outputs.

            // Current implementation ignores extensions

            // 24. Update 'credentialRecord' with new state values:
            // 24.1 Update 'credentialRecord.signCount' to the value of 'authData.signCount'.
            // 24.2 Update 'credentialRecord.backupState' to the value of 'currentBs'.
            // 24.3 If 'credentialRecord.uvInitialized' is 'false',
            //      update it to the value of the 'UV' bit in the 'flags' in 'authData'.
            //      This change SHOULD require authorization by an additional authentication factor
            //      equivalent to WebAuthn user verification; if not authorized, skip this step.
            // If the Relying Party performs additional security checks beyond these WebAuthn authentication ceremony steps,
            // the above state updates SHOULD be deferred to after those additional checks are completed successfully.
            var credentialRecordUpdateResult = UpdateCredentialRecord(
                credentialRecord,
                authData);
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

            // 25. If all the above steps are successful,
            // continue the authentication ceremony as appropriate.
            // Otherwise, fail the authentication ceremony.
            // https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges
            // The challenge is stored only until the operation is complete, so the same response cannot complete the ceremony again.
            await CeremonyStorage.RemoveAsync(context, request.AuthenticationCeremonyId, cancellationToken);
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
    ///     Checks whether the lifetime of the authentication ceremony is over, so it can no longer be completed.
    /// </summary>
    /// <param name="authenticationCeremonyParameters">Authentication ceremony parameters.</param>
    /// <returns><see langword="true" /> if the authentication ceremony has expired, otherwise - <see langword="false" />.</returns>
    protected virtual bool IsCeremonyExpired(AuthenticationCeremonyParameters authenticationCeremonyParameters)
    {
        ArgumentNullException.ThrowIfNull(authenticationCeremonyParameters);
        return TimeProvider.GetPreciseUtcDateTime() > authenticationCeremonyParameters.ExpiresAt;
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
    /// <param name="credentialRecord">The CredentialRecord value that needs to be updated. </param>
    /// <param name="authData">The updated <a href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">authData</a> value.</param>
    /// <returns>The result of updating the <a href="https://www.w3.org/TR/webauthn-3/#credential-record">credentialRecord</a>.</returns>
    protected virtual CredentialRecordUpdateResult UpdateCredentialRecord(
        CredentialRecord credentialRecord,
        AbstractAuthenticatorData authData)
    {
        ArgumentNullException.ThrowIfNull(credentialRecord);
        ArgumentNullException.ThrowIfNull(authData);
        // If 'credentialRecord.uvInitialized' is false,
        // update it to the value of the 'UV' bit in the 'flags' in 'authData'.
        // This change SHOULD require authorization by an additional authentication factor
        // equivalent to WebAuthn user verification; if not authorized, skip this step.
        var uv = (authData.Flags & AuthenticatorDataFlags.UserVerified) is AuthenticatorDataFlags.UserVerified;
        var userVerificationFlagMayBeUpdatedToTrue = !credentialRecord.UvInitialized && uv;
        var bs = (authData.Flags & AuthenticatorDataFlags.BackupState) is AuthenticatorDataFlags.BackupState;
        var updatedCredentialRecord = new CredentialRecord(
            credentialRecord.Type,
            credentialRecord.Id,
            credentialRecord.PublicKey,
            authData.SignCount, // Update credentialRecord.signCount to the value of authData.signCount.
            credentialRecord.Transports,
            credentialRecord.UvInitialized,
            credentialRecord.BackupEligible,
            bs,
            credentialRecord.AttestationObject,
            credentialRecord.AttestationClientDataJSON);
        return new(updatedCredentialRecord, userVerificationFlagMayBeUpdatedToTrue);
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
    ///     Computes the recommended actions that need to be taken after the authentication ceremony based on <a href="https://www.w3.org/TR/webauthn-3/#sctn-credential-backup">credential backup state</a>.
    /// </summary>
    /// <param name="currentBe">The value of the <a href="https://www.w3.org/TR/webauthn-3/#authdata-flags-be">backup eligibility (BE)</a> flag for the credential obtained in the current authentication ceremony.</param>
    /// <param name="currentBs">The value of the <a href="https://www.w3.org/TR/webauthn-3/#authdata-flags-bs">backup state (BS)</a> flag for the credential obtained in the current authentication ceremony.</param>
    /// <param name="credentialRecordBackupState">The previous value of the <a href="https://www.w3.org/TR/webauthn-3/#authdata-flags-be">backup eligibility (BE)</a> flag, which was previously saved for the credential used in the authentication ceremony.</param>
    /// <returns>An array of recommended actions to be performed after the authentication ceremony based on the <a href="https://www.w3.org/TR/webauthn-3/#sctn-credential-backup">credential backup state</a>. Can be an empty array, cannot be <see langword="null" />.</returns>
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
    ///     An array of public key descriptors for the authentication ceremony. If <see langword="null" />, then only <a href="https://www.w3.org/TR/webauthn-3/#discoverable-credential">discoverable credentials</a> will be utilized in this authentication
    ///     ceremony.
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
        Level = LogLevel.Warning,
        Message = "Authentication ceremony not found")]
    public static partial void AuthenticationCeremonyNotFound(this ILogger logger);

    /// <summary>
    ///     The authentication ceremony has expired and can no longer be completed
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The authentication ceremony has expired and can no longer be completed")]
    public static partial void AuthenticationCeremonyExpired(this ILogger logger);

    /// <summary>
    ///     Failed to decode AuthenticationResponseJSON
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode AuthenticationResponseJSON")]
    public static partial void FailedToDecodeAuthenticationResponseJson(this ILogger logger);

    /// <summary>
    ///     The 'id' and 'rawId' of the credential don't represent the same credential ID
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'id' and 'rawId' of the credential don't represent the same credential ID")]
    public static partial void CredentialIdDoesNotMatchRawId(this ILogger logger);

    /// <summary>
    ///     'clientData.crossOrigin' is true, but the Relying Party doesn't expect the credential to be used within a cross-origin iframe
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "'clientData.crossOrigin' is true, but the Relying Party doesn't expect the credential to be used within a cross-origin iframe")]
    public static partial void UnexpectedCrossOrigin(this ILogger logger);

    /// <summary>
    ///     The received credential.id is not included in the list specified in options.allowCredentials
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The received credential.id is not included in the list specified in options.allowCredentials")]
    public static partial void InvalidCredentialId(this ILogger logger);

    /// <summary>
    ///     Failed to find an existing credential with the specified Id
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to find an existing credential with the specified Id")]
    public static partial void CredentialNotFound(this ILogger logger);

    /// <summary>
    ///     The credential obtained from the storage does not match the parameters of the authentication ceremony
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The credential obtained from the storage does not match the parameters of the authentication ceremony")]
    public static partial void CredentialMismatch(this ILogger logger);

    /// <summary>
    ///     response.userHandle does not equal the user handle of the user account
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "response.userHandle does not equal the user handle of the user account")]
    public static partial void ResponseUserHandleMismatch(this ILogger logger);

    /// <summary>
    ///     response.userHandle is not present
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "response.userHandle is not present")]
    public static partial void UserHandleNotPresentInResponse(this ILogger logger);

    /// <summary>
    ///     Failed to decode response.AuthenticatorData
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode response.AuthenticatorData")]
    public static partial void FailedToDecodeResponseAuthenticatorData(this ILogger logger);

    /// <summary>
    ///     Failed to decode response.clientDataJSON
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode response.clientDataJSON")]
    public static partial void FailedToDecodeResponseClientDataJson(this ILogger logger);

    /// <summary>
    ///     The 'clientData.type' is incorrect, as it expected 'webauthn.get' but received '{ClientDataType}'
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="clientDataType">The received 'clientData.type' value.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'clientData.type' is incorrect, as it expected 'webauthn.get' but received '{ClientDataType}'")]
    public static partial void IncorrectClientDataType(this ILogger logger, string clientDataType);

    /// <summary>
    ///     The challenge in the authentication completion request doesn't match the one generated for this authentication ceremony
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The challenge in the authentication completion request doesn't match the one generated for this authentication ceremony")]
    public static partial void ChallengeMismatch(this ILogger logger);

    /// <summary>
    ///     Invalid value for origin: '{ClientDataOrigin}'
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="clientDataOrigin">The origin obtained from clientData.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Invalid value for origin: '{ClientDataOrigin}'")]
    public static partial void InvalidOrigin(this ILogger logger, string clientDataOrigin);

    /// <summary>
    ///     Invalid value for topOrigin: '{ClientDataTopOrigin}'
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="clientDataTopOrigin">The topOrigin obtained from clientData.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Invalid value for topOrigin: '{ClientDataTopOrigin}'")]
    public static partial void InvalidTopOrigin(this ILogger logger, string clientDataTopOrigin);

    /// <summary>
    ///     The 'rpIdHash' in 'authData' does not match the SHA-256 hash of the RP ID expected by the Relying Party
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'rpIdHash' in 'authData' does not match the SHA-256 hash of the RP ID expected by the Relying Party")]
    public static partial void RpIdHashMismatch(this ILogger logger);

    /// <summary>
    ///     User Present bit in 'authData.flags' isn't set
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "User Present bit in 'authData.flags' isn't set")]
    public static partial void UserPresentBitNotSet(this ILogger logger);

    /// <summary>
    ///     User Verification bit in 'authData.flags' is required, but not set
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "User Verification bit in 'authData.flags' is required, but not set")]
    public static partial void UserVerificationBitNotSet(this ILogger logger);

    /// <summary>
    ///     'authData.flags' contains an invalid combination of Backup Eligibility (BE) and Backup State (BS) flags
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "'authData.flags' contains an invalid combination of Backup Eligibility (BE) and Backup State (BS) flags")]
    public static partial void InvalidBeBsFlagsCombination(this ILogger logger);

    /// <summary>
    ///     Backup Eligible bit in 'authData.flags' is required, but not set
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Backup Eligible bit in 'authData.flags' is required, but not set")]
    public static partial void BackupEligibleBitNotSet(this ILogger logger);

    /// <summary>
    ///     Backup Eligible bit in 'authData.flags' is set, but it shouldn't be
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Backup Eligible bit in 'authData.flags' is set, but it shouldn't be")]
    public static partial void BackupEligibleBitSet(this ILogger logger);

    /// <summary>
    ///     Failed to transform the public key of the found credentialRecord into a CoseKey
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to transform the public key of the found credentialRecord into a CoseKey")]
    public static partial void FailedToTransformCredentialPublicKey(this ILogger logger);

    /// <summary>
    ///     Invalid signature
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Invalid signature")]
    public static partial void InvalidSignature(this ILogger logger);

    /// <summary>
    ///     The obtained signCount is less than or equal to the one that was saved earlier
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The obtained signCount is less than or equal to the one that was saved earlier")]
    public static partial void AbortBySignCount(this ILogger logger);

    /// <summary>
    ///     The obtained signCount {ReceivedSignCount} is less than or equal to the saved one {StoredSignCount}, the authenticator may be cloned. The ceremony continues by Relying Party policy
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="receivedSignCount">The signCount obtained in the current authentication ceremony.</param>
    /// <param name="storedSignCount">The signCount saved in the credential record.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The obtained signCount {ReceivedSignCount} is less than or equal to the saved one {StoredSignCount}, the authenticator may be cloned. The ceremony continues by Relying Party policy")]
    public static partial void SignCountNotIncreased(this ILogger logger, uint receivedSignCount, uint storedSignCount);

    /// <summary>
    ///     Failed to update user credential record
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to update user credential record")]
    public static partial void CredentialStorageUpdateFailed(this ILogger logger);
}
