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
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;
using WebAuthn.Net.Services.Common.AttestationObjectDecoder;
using WebAuthn.Net.Services.Common.AttestationObjectDecoder.Models;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AttestationTrustPathValidator;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models.Enums;
using WebAuthn.Net.Services.Common.ChallengeGenerator;
using WebAuthn.Net.Services.Common.ClientDataDecoder;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateCredential;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.RegistrationCeremony.Services.PublicKeyCredentialCreationOptionsEncoder;
using WebAuthn.Net.Services.RegistrationCeremony.Services.RegistrationResponseDecoder;
using WebAuthn.Net.Services.Serialization.Cose.Models;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Static;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.Credential.Models;
using WebAuthn.Net.Storage.RegistrationCeremony;
using WebAuthn.Net.Storage.RegistrationCeremony.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation;

/// <summary>
///     Default implementation of <see cref="IRegistrationCeremonyService" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultRegistrationCeremonyService<TContext>
    : IRegistrationCeremonyService
    where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     Constructs <see cref="DefaultRegistrationCeremonyService{TContext}" />.
    /// </summary>
    /// <param name="options">Accessor for getting the current value of global options.</param>
    /// <param name="contextFactory">Factory for creating a WebAuthn operation context.</param>
    /// <param name="rpIdProvider">Provider of the rpId value based on the <see cref="HttpContext" />.</param>
    /// <param name="rpOriginProvider">Provider of the origin value based on the <see cref="HttpContext" />.</param>
    /// <param name="challengeGenerator">Generator of challenges for WebAuthn ceremonies.</param>
    /// <param name="timeProvider">Current time provider.</param>
    /// <param name="publicKeyCredentialCreationOptionsEncoder">Encoder for transforming <see cref="PublicKeyCredentialCreationOptions" /> into a model suitable for JSON serialization.</param>
    /// <param name="credentialStorage">Credential storage. This is where the credentials are located, providing methods for storing credentials that are created during the registration ceremony, as well as methods for accessing them during the authentication ceremony.</param>
    /// <param name="ceremonyStorage">Storage for registration ceremony data.</param>
    /// <param name="registrationResponseDecoder">Decoder for <see cref="RegistrationResponseJSON" /> (<a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-pkcredential">PublicKeyCredential</a>) from a model suitable for JSON serialization to a typed representation.</param>
    /// <param name="clientDataDecoder">Decoder for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-client-data">clientData</a> from JSON into a typed representation.</param>
    /// <param name="attestationObjectDecoder">Decoder for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#fig-attStructs">attestationObject</a> from binary into a typed representation.</param>
    /// <param name="authenticatorDataDecoder">Decoder for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> from binary into a typed representation.</param>
    /// <param name="attestationStatementDecoder">Decoder for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a> from CBOR into a typed representation.</param>
    /// <param name="attestationStatementVerifier">Verifier of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a>.</param>
    /// <param name="attestationTrustPathValidator"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-trust-path">Attestation trust path</a> validator. It validates that the attestation statement is trustworthy.</param>
    /// <param name="counters">Counters for registration ceremony metrics.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultRegistrationCeremonyService(
        IOptionsMonitor<WebAuthnOptions> options,
        IWebAuthnContextFactory<TContext> contextFactory,
        IRelyingPartyIdProvider rpIdProvider,
        IRelyingPartyOriginProvider rpOriginProvider,
        IChallengeGenerator challengeGenerator,
        ITimeProvider timeProvider,
        IPublicKeyCredentialCreationOptionsEncoder publicKeyCredentialCreationOptionsEncoder,
        ICredentialStorage<TContext> credentialStorage,
        IRegistrationCeremonyStorage<TContext> ceremonyStorage,
        IRegistrationResponseDecoder registrationResponseDecoder,
        IClientDataDecoder clientDataDecoder,
        IAttestationObjectDecoder attestationObjectDecoder,
        IAuthenticatorDataDecoder authenticatorDataDecoder,
        IAttestationStatementDecoder attestationStatementDecoder,
        IAttestationStatementVerifier<TContext> attestationStatementVerifier,
        IAttestationTrustPathValidator attestationTrustPathValidator,
        IRegistrationCeremonyCounters counters,
        ILogger<DefaultRegistrationCeremonyService<TContext>> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(contextFactory);
        ArgumentNullException.ThrowIfNull(rpIdProvider);
        ArgumentNullException.ThrowIfNull(rpOriginProvider);
        ArgumentNullException.ThrowIfNull(challengeGenerator);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(publicKeyCredentialCreationOptionsEncoder);
        ArgumentNullException.ThrowIfNull(credentialStorage);
        ArgumentNullException.ThrowIfNull(ceremonyStorage);
        ArgumentNullException.ThrowIfNull(registrationResponseDecoder);
        ArgumentNullException.ThrowIfNull(clientDataDecoder);
        ArgumentNullException.ThrowIfNull(attestationObjectDecoder);
        ArgumentNullException.ThrowIfNull(authenticatorDataDecoder);
        ArgumentNullException.ThrowIfNull(attestationStatementDecoder);
        ArgumentNullException.ThrowIfNull(attestationStatementVerifier);
        ArgumentNullException.ThrowIfNull(attestationTrustPathValidator);
        ArgumentNullException.ThrowIfNull(counters);
        ArgumentNullException.ThrowIfNull(logger);
        Options = options;
        ContextFactory = contextFactory;
        RpIdProvider = rpIdProvider;
        RpOriginProvider = rpOriginProvider;
        ChallengeGenerator = challengeGenerator;
        TimeProvider = timeProvider;
        PublicKeyCredentialCreationOptionsEncoder = publicKeyCredentialCreationOptionsEncoder;
        CredentialStorage = credentialStorage;
        CeremonyStorage = ceremonyStorage;
        RegistrationResponseDecoder = registrationResponseDecoder;
        ClientDataDecoder = clientDataDecoder;
        AttestationObjectDecoder = attestationObjectDecoder;
        AuthenticatorDataDecoder = authenticatorDataDecoder;
        AttestationStatementDecoder = attestationStatementDecoder;
        AttestationStatementVerifier = attestationStatementVerifier;
        AttestationTrustPathValidator = attestationTrustPathValidator;
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
    ///     Encoder for transforming <see cref="PublicKeyCredentialCreationOptions" /> into a model suitable for JSON serialization.
    /// </summary>
    protected IPublicKeyCredentialCreationOptionsEncoder PublicKeyCredentialCreationOptionsEncoder { get; }

    /// <summary>
    ///     Credential storage. This is where the credentials are located, providing methods for storing credentials that are created during the registration ceremony, as well as methods for accessing them during the authentication ceremony.
    /// </summary>
    protected ICredentialStorage<TContext> CredentialStorage { get; }

    /// <summary>
    ///     Storage for registration ceremony data.
    /// </summary>
    protected IRegistrationCeremonyStorage<TContext> CeremonyStorage { get; }

    /// <summary>
    ///     Decoder for <see cref="RegistrationResponseJSON" /> (<a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-pkcredential">PublicKeyCredential</a>) from a model suitable for JSON serialization to a typed representation.
    /// </summary>
    protected IRegistrationResponseDecoder RegistrationResponseDecoder { get; }

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
    ///     Counters for registration ceremony metrics.
    /// </summary>
    protected IRegistrationCeremonyCounters Counters { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultRegistrationCeremonyService<TContext>> Logger { get; }

    /// <inheritdoc />
    public virtual async Task<BeginRegistrationCeremonyResult> BeginCeremonyAsync(
        HttpContext httpContext,
        BeginRegistrationCeremonyRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        Counters.IncrementBeginCeremonyStart();
        await using var context = await ContextFactory.CreateAsync(httpContext, cancellationToken);
        var challenge = ChallengeGenerator.GenerateChallenge(request.ChallengeSize);
        var rpId = await RpIdProvider.GetAsync(httpContext, cancellationToken);
        var credentialsToExclude = await GetCredentialsToExcludeAsync(
            context,
            rpId,
            request.User.Id,
            request.ExcludeCredentials,
            cancellationToken);
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

        var expectedRpParameters = new RegistrationCeremonyRpParameters(rpId, origins, allowIframe, topOrigins);
        var timeout = GetTimeout(request);
        var createdAt = TimeProvider.GetRoundUtcDateTime();
        var expiresAt = GetExpiresAtUtc(createdAt, timeout);
        var options = CreatePublicKeyCredentialCreationOptions(request, timeout, rpId, challenge, credentialsToExclude);
        var outputOptions = PublicKeyCredentialCreationOptionsEncoder.Encode(options);
        var registrationCeremonyParameters = new RegistrationCeremonyParameters(
            options,
            expectedRpParameters,
            createdAt,
            expiresAt);
        var ceremonyId = await CeremonyStorage.SaveAsync(context, registrationCeremonyParameters, cancellationToken);
        await context.CommitAsync(cancellationToken);
        var result = new BeginRegistrationCeremonyResult(outputOptions, ceremonyId);
        Counters.IncrementBeginCeremonyEnd(true);
        return result;
    }

    /// <inheritdoc />
    public virtual async Task<Result<CompleteRegistrationCeremonyResult>> CompleteCeremonyAsync(
        HttpContext httpContext,
        CompleteRegistrationCeremonyRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        Counters.IncrementCompleteCeremonyStart();
        using (Logger.BeginCompleteRegistrationCeremonyScope(request.RegistrationCeremonyId))
        await using (var context = await ContextFactory.CreateAsync(httpContext, cancellationToken))
        {
            var registrationCeremonyParameters = await CeremonyStorage.FindAsync(
                context,
                request.RegistrationCeremonyId,
                cancellationToken);
            if (registrationCeremonyParameters is null)
            {
                Logger.RegistrationCeremonyNotFound();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-registering-a-new-credential
            // 1. Let 'options' be a new 'PublicKeyCredentialCreationOptions' structure configured to the Relying Party's needs for the ceremony.
            var options = registrationCeremonyParameters.Options;

            // 2. Call navigator.credentials.create() and pass 'options' as the 'publicKey' option.
            // Let 'credential' be the result of the successfully resolved promise.
            // If the promise is rejected, abort the ceremony with a user-visible error, or otherwise guide the user experience as might be determinable
            // from the context available in the rejected promise. For example if the promise is rejected with an error code equivalent to "InvalidStateError",
            // the user might be instructed to use a different authenticator.
            // For information on different error contexts and the circumstances leading to them, see §6.3.2 The authenticatorMakeCredential Operation.
            var credentialResult = RegistrationResponseDecoder.Decode(request.Response);
            if (credentialResult.HasError)
            {
                Logger.FailedToDecodeRegistrationResponseJson();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            var credential = credentialResult.Ok;

            // 3. Let 'response' be 'credential.response'. If 'response' is not an instance of 'AuthenticatorAttestationResponse', abort the ceremony with a user-visible error.
            var response = credential.Response;

            // 4. Let 'clientExtensionResults' be the result of calling 'credential.getClientExtensionResults()'.
            //var clientExtensionResults = credential.ClientExtensionResults;

            // 5. Let 'JSONtext' be the result of running UTF-8 decode on the value of 'response.clientDataJSON'.
            // Note: Using any implementation of UTF-8 decode is acceptable as long as it yields the same result as that yielded by the UTF-8 decode algorithm.
            // In particular, any leading byte order mark (BOM) MUST be stripped.
            // ReSharper disable once InconsistentNaming
            var JSONtext = Encoding.UTF8.GetString(response.ClientDataJson);

            // 6. Let 'C', the client data claimed as collected during the credential creation,
            // be the result of running an implementation-specific JSON parser on 'JSONtext'.
            // Note: 'C' may be any implementation-specific data structure representation, as long as C's components are referenceable,
            // as required by this algorithm.
            var clientDataResult = ClientDataDecoder.Decode(JSONtext);
            if (clientDataResult.HasError)
            {
                Logger.FailedToDecodeClientData();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            // ReSharper disable once InconsistentNaming
            var C = clientDataResult.Ok;

            // 7. Verify that the value of 'C.type' is "webauthn.create".
            if (C.Type is not "webauthn.create")
            {
                Logger.IncorrectClientDataType(C.Type);
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            // 8. Verify that the value of 'C.challenge' equals the base64url encoding of 'options.challenge'.
            if (!string.Equals(C.Challenge, Base64Url.Encode(options.Challenge), StringComparison.Ordinal))
            {
                Logger.ChallengeMismatch();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            // 9. Verify that the value of 'C.origin' is an origin expected by the Relying Party. See §13.4.9 Validating the origin of a credential for guidance.
            var allowedOrigin = registrationCeremonyParameters.ExpectedRp.Origins.FirstOrDefault(x => string.Equals(x, C.Origin, StringComparison.Ordinal));
            if (allowedOrigin is null)
            {
                Logger.InvalidOrigin(C.Origin);
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            // 10. If 'C.topOrigin' is present:
            if (C.TopOrigin is not null)
            {
                //   1. Verify that the Relying Party expects that this credential would have been created within an iframe that is not same-origin with its ancestors.
                //   2. Verify that the value of C.topOrigin matches the origin of a page that the Relying Party expects to be sub-framed within. See §13.4.9 Validating the origin of a credential for guidance.
                if (!registrationCeremonyParameters.ExpectedRp.AllowIframe)
                {
                    if (!string.Equals(allowedOrigin, C.TopOrigin, StringComparison.Ordinal))
                    {
                        Logger.InvalidTopOrigin(C.TopOrigin);
                        Counters.IncrementCompleteCeremonyEnd(false);
                        return Result<CompleteRegistrationCeremonyResult>.Fail();
                    }
                }
                else
                {
                    if (!registrationCeremonyParameters.ExpectedRp.TopOrigins.Any(x => string.Equals(x, C.TopOrigin, StringComparison.Ordinal)))
                    {
                        Logger.InvalidTopOrigin(C.TopOrigin);
                        Counters.IncrementCompleteCeremonyEnd(false);
                        return Result<CompleteRegistrationCeremonyResult>.Fail();
                    }
                }
            }

            // 11. Let 'hash' be the result of computing a hash over 'response.clientDataJSON' using SHA-256.
            var hash = SHA256.HashData(response.ClientDataJson);

            // 12. Perform CBOR decoding on the 'attestationObject' field of the 'AuthenticatorAttestationResponse' structure
            // (see 3. Let 'response' be 'credential.response')
            // to obtain the attestation statement format 'fmt', the authenticator data 'authData', and the attestation statement 'attStmt'.
            var attestationObjectResult = AttestationObjectDecoder.Decode(response.AttestationObject);
            if (attestationObjectResult.HasError)
            {
                Logger.AttestationObjectDecodeFailed();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            var fmt = attestationObjectResult.Ok.Fmt;
            // Attestation objects provided in an AuthenticatorAttestationResponse structure (i.e. as the result of a create() operation)
            // contain at least the three keys shown in the previous figure: fmt, attStmt, and authData.
            if (attestationObjectResult.Ok.AuthData is null)
            {
                Logger.NullAuthDataForRegistration();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            var authDataResult = AuthenticatorDataDecoder.Decode(attestationObjectResult.Ok.AuthData);
            if (authDataResult.HasError)
            {
                Logger.FailedToDecodeAuthData();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            // §6.5.2. Attested Credential Data
            // Attested credential data is always present in any authenticator data that results from a create() operation.
            if (authDataResult.Ok is not AttestedAuthenticatorData authData)
            {
                Logger.AttestedCredentialDataIsNull();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            var attStmtResult = AttestationStatementDecoder.Decode(attestationObjectResult.Ok.AttStmt, fmt);
            if (attStmtResult.HasError)
            {
                Logger.FailedToDecodeAttStmt();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            var attStmt = attStmtResult.Ok;

            // 13. Verify that the 'rpIdHash' in 'authData' is the SHA-256 hash of the 'RP ID' expected by the Relying Party.
            var authDataRpIdHash = authData.RpIdHash;
            var expectedRpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(registrationCeremonyParameters.ExpectedRp.RpId));
            if (!authDataRpIdHash.AsSpan().SequenceEqual(expectedRpIdHash.AsSpan()))
            {
                Logger.RpIdHashMismatch();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            // 14. Verify that the UP bit of the 'flags' in 'authData' is set.
            if ((authData.Flags & AuthenticatorDataFlags.UserPresent) is not AuthenticatorDataFlags.UserPresent)
            {
                Logger.UserPresentBitNotSet();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            // 15. If the Relying Party requires user verification for this registration, verify that the UV bit of the 'flags' in 'authData' is set.
            var userVerificationRequired = options.AuthenticatorSelection?.UserVerification is UserVerificationRequirement.Required;
            var uvInitialized = (authData.Flags & AuthenticatorDataFlags.UserVerified) is AuthenticatorDataFlags.UserVerified;
            if (userVerificationRequired && !uvInitialized)
            {
                Logger.UserVerificationBitNotSet();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            // 16. If the BE bit of the 'flags' in 'authData' is not set, verify that the BS bit is not set.
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
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            // 17. If the Relying Party uses the credential's backup eligibility to inform its user experience flows and/or policies,
            // evaluate the BE bit of the flags in authData.
            // 18. If the Relying Party uses the credential's backup state to inform its user experience flows and/or policies,
            // evaluate the BS bit of the flags in authData.

            // 19. Verify that the 'alg' parameter in the credential public key in 'authData' matches the 'alg' attribute of one of the items in 'options.pubKeyCredParams'.
            // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attested-credential-data

            var expectedAlgorithms = options.PubKeyCredParams.Select(x => x.Alg).ToHashSet();
            if (!expectedAlgorithms.Contains(authData.AttestedCredentialData.CredentialPublicKey.Alg))
            {
                Logger.AuthDataAlgDoesntMatchPubKeyCredParams();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }
            // 20. Verify that the values of the client extension outputs in 'clientExtensionResults' and the authenticator extension outputs in the extensions
            // in 'authData' are as expected, considering the client extension input values that were given in 'options.extensions'
            // and any specific policy of the Relying Party regarding unsolicited extensions, i.e., those that were not specified as part of 'options.extensions'.
            // In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.

            // extensions not implemented


            // 21. Determine the attestation statement format by performing a USASCII case-sensitive match on 'fmt'
            // against the set of supported WebAuthn Attestation Statement Format Identifier values.
            // An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the
            // IANA "WebAuthn Attestation Statement Format Identifiers" registry [IANA-WebAuthn-Registries] established by [RFC8809].
            // 22. Verify that 'attStmt' is a correct attestation statement, conveying a valid attestation signature,
            // by using the attestation statement format 'fmt' verification procedure given 'attStmt', 'authData' and 'hash'.
            // Each attestation statement format specifies its own verification procedure.
            // See §8 Defined Attestation Statement Formats for the initially-defined formats, and [IANA-WebAuthn-Registries] for the up-to-date list.

            var attStmtVerificationResult = await AttestationStatementVerifier.VerifyAttestationStatementAsync(
                context,
                fmt,
                attStmt,
                authData,
                hash,
                cancellationToken);
            if (attStmtVerificationResult.HasError)
            {
                Logger.InvalidAttStmt();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            var attStmtVerification = attStmtVerificationResult.Ok;

            // 23. If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates)
            // for that attestation type and attestation statement format 'fmt', from a trusted source or from policy.
            // For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information,
            // using the 'aaguid' in the 'attestedCredentialData' in 'authData'.

            // 24. Assess the attestation trustworthiness using the outputs of the verification procedure in step 21, as follows:
            // 24.1 If no attestation was provided, verify that None attestation is acceptable under Relying Party policy.
            if (attStmtVerification.AttestationType == AttestationType.None && !Options.CurrentValue.AttestationTypes.None.IsAcceptable)
            {
                Logger.NoneAttestationDisallowed();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            // 24.2 If self attestation was used, verify that self attestation is acceptable under Relying Party policy.
            if (attStmtVerification.AttestationType == AttestationType.Self && !Options.CurrentValue.AttestationTypes.Self.IsAcceptable)
            {
                Logger.SelfAttestationDisallowed();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            // 24.3 Otherwise, use the X.509 certificates returned as the attestation trust path from the verification procedure
            // to verify that the attestation public key either correctly chains up to an acceptable root certificate,
            // or is itself an acceptable certificate (i.e., it and the root certificate obtained in Step 22 may be the same).
            if (!AttestationTrustPathValidator.IsValid(attStmtVerification))
            {
                Logger.AttestationTrustPathIsInvalid();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            // 25. Verify that the credentialId is ≤ 1023 bytes. Credential IDs larger than this many bytes SHOULD cause the RP to fail this registration ceremony.
            if (authData.AttestedCredentialData.CredentialId.Length > 1023)
            {
                Logger.CredentialIdIsTooBig();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            // 26. Verify that the credentialId is not yet registered for any user.
            // If the credentialId is already known then the Relying Party SHOULD fail this registration ceremony.
            // 27. If the attestation statement 'attStmt' verified successfully and is found to be trustworthy,
            // then create and store a new credential record in the user account that was denoted in options.user
            // 28. If the attestation statement attStmt successfully verified but is not trustworthy per step 23 above,
            // the Relying Party SHOULD fail the registration ceremony.
            var credentialRecord = CreateCredentialRecord(
                credential,
                authData,
                uvInitialized,
                currentBe,
                currentBs,
                response);
            var userCredentialRecord = await CreateUserCredentialRecordAsync(
                context,
                registrationCeremonyParameters,
                request,
                credentialRecord,
                attestationObjectResult.Ok,
                authData,
                attStmt,
                attStmtVerification,
                cancellationToken);
            var credentialIdNotRegisteredForAnyUser = await CredentialStorage.SaveIfNotRegisteredForOtherUserAsync(
                context,
                userCredentialRecord,
                cancellationToken);
            if (!credentialIdNotRegisteredForAnyUser)
            {
                Logger.CredentialIdExist();
                Counters.IncrementCompleteCeremonyEnd(false);
                return Result<CompleteRegistrationCeremonyResult>.Fail();
            }

            await CeremonyStorage.RemoveAsync(context, request.RegistrationCeremonyId, cancellationToken);
            // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-credential-backup
            // When the BE flag is set to 0
            var requiringAdditionalAuthenticators = !currentBe;
            var successfulResult = new CompleteRegistrationCeremonyResult(
                requiringAdditionalAuthenticators,
                userCredentialRecord.UserHandle);
            var result = Result<CompleteRegistrationCeremonyResult>.Success(successfulResult);
            await context.CommitAsync(cancellationToken);
            Counters.IncrementCompleteCeremonyEnd(true);
            return result;
        }
    }


    /// <summary>
    ///     Computes the expiration date of the registration ceremony's lifetime.
    /// </summary>
    /// <param name="createdAt">Creation date of the registration ceremony.</param>
    /// <param name="timeout">Registration ceremony timeout in milliseconds</param>
    /// <returns>Expiration date of the registration ceremony's lifetime, after which its data is expected to be deleted.</returns>
    protected static DateTimeOffset GetExpiresAtUtc(DateTimeOffset createdAt, uint timeout)
    {
        var expiresAtMilliseconds = createdAt.ToUnixTimeMilliseconds() + timeout;
        return DateTimeOffset.FromUnixTimeMilliseconds(expiresAtMilliseconds);
    }

    /// <summary>
    ///     Computes the registration ceremony timeout in milliseconds.
    /// </summary>
    /// <param name="request">Request containing parameters for generating the registration ceremony options.</param>
    /// <returns>Registration ceremony timeout in milliseconds.</returns>
    protected virtual uint GetTimeout(BeginRegistrationCeremonyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Timeout.HasValue)
        {
            return request.Timeout.Value;
        }

        return Options.CurrentValue.RegistrationCeremony.DefaultTimeout;
    }

    /// <summary>
    ///     Returns the descriptors of credentials that will be included in the resulting set of <see cref="PublicKeyCredentialCreationOptions.ExcludeCredentials" /> options of the registration ceremony.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="rpId">The rpId for which the descriptor set is being formed.</param>
    /// <param name="userHandle">The unique identifier of the user for whom the descriptor set is being formed.</param>
    /// <param name="options">Parameters for forming a set of descriptors, obtained from the request to create registration ceremony options.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>An array containing at least one descriptor or <see langword="null" />.</returns>
    protected virtual async Task<PublicKeyCredentialDescriptor[]?> GetCredentialsToExcludeAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        RegistrationCeremonyExcludeCredentials options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        if (options.ExcludeAllExistingKeys)
        {
            var existingKeys = await CredentialStorage.FindDescriptorsAsync(context, rpId, userHandle, cancellationToken);
            if (existingKeys.Length > 0)
            {
                return existingKeys;
            }

            return null;
        }

        if (options.ExcludeManuallySpecified)
        {
            var existingKeys = await CredentialStorage.FindDescriptorsAsync(context, rpId, userHandle, cancellationToken);
            if ((existingKeys.Length > 0) is not true)
            {
                return null;
            }

            var resultKeysToExclude = new List<PublicKeyCredentialDescriptor>(options.ManuallySpecifiedKeysToExclude.Length);
            foreach (var manualKey in options.ManuallySpecifiedKeysToExclude)
            {
                var existingKey = existingKeys.FirstOrDefault(x =>
                    x.Type == manualKey.Type
                    && x.Id.AsSpan().SequenceEqual(manualKey.Id));
                if (existingKey is not null)
                {
                    resultKeysToExclude.Add(existingKey);
                }
            }

            if (resultKeysToExclude.Count > 0)
            {
                return resultKeysToExclude.ToArray();
            }
        }

        return null;
    }

    /// <summary>
    ///     Creates options with which the registration ceremony will be performed.
    /// </summary>
    /// <param name="request">Request containing parameters for generating the registration ceremony options.</param>
    /// <param name="timeout">Registration ceremony timeout in milliseconds.</param>
    /// <param name="rpId">rpId on which the registration ceremony will be performed.</param>
    /// <param name="challenge">Challenge that will be used in the registration ceremony.</param>
    /// <param name="excludeCredentials">
    ///     Array of public key descriptors for the registration ceremony. If <see langword="null" />, the mechanism that ensures that a new credential is not created on an authenticator that already contains a credential mapped to this user account will not
    ///     work.
    /// </param>
    /// <returns>Options with which the registration ceremony will be performed.</returns>
    protected virtual PublicKeyCredentialCreationOptions CreatePublicKeyCredentialCreationOptions(
        BeginRegistrationCeremonyRequest request,
        uint timeout,
        string rpId,
        byte[] challenge,
        PublicKeyCredentialDescriptor[]? excludeCredentials)
    {
        ArgumentNullException.ThrowIfNull(request);
        var rp = new PublicKeyCredentialRpEntity(
            request.RpDisplayName,
            rpId);
        var pubKeyCredParams = request.PubKeyCredParams
            .Select(static x => new PublicKeyCredentialParameters(PublicKeyCredentialType.PublicKey, x))
            .ToArray();
        var publicKeyOptions = new PublicKeyCredentialCreationOptions(
            rp,
            request.User,
            challenge,
            pubKeyCredParams,
            timeout,
            excludeCredentials,
            request.AuthenticatorSelection,
            request.Hints,
            request.Attestation,
            request.AttestationFormats,
            request.Extensions);
        return publicKeyOptions;
    }

    /// <summary>
    ///     Creates a <see cref="CredentialRecord" /> that stores the properties of the registered public key.
    /// </summary>
    /// <param name="credential">PublicKeyCredential. The response received from the authenticator during the registration ceremony.</param>
    /// <param name="authData">Authenticator Data (which has attestedCredentialData).</param>
    /// <param name="uvInitialized">The value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-uv">user verified (UV)</a> flag in authData.</param>
    /// <param name="backupEligible">The value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-be">backup eligibility (BE)</a> flag in authData.</param>
    /// <param name="backupState">The value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-bs">backup state (BS)</a> flag in authData.</param>
    /// <param name="response">Information about Public Key Credential</param>
    /// <returns>Instance of <see cref="CredentialRecord" />.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="credential" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="authData" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="response" /> is <see langword="null" /></exception>
    /// <exception cref="InvalidOperationException">The type of <see cref="AttestedCredentialData.CredentialPublicKey" /> does not match <see cref="AbstractCoseKey.Kty" /></exception>
    protected virtual CredentialRecord CreateCredentialRecord(
        RegistrationResponse credential,
        AttestedAuthenticatorData authData,
        bool uvInitialized,
        bool backupEligible,
        bool backupState,
        AuthenticatorAttestationResponse response)
    {
        // type - credential.type
        // id - credential.id or credential.rawId, whichever format is preferred by the Relying Party.
        // publicKey - The credential public key in authData.
        // signCount - authData.signCount.
        // uvInitialized - The value of the UV flag in authData.
        // transports - The value returned from response.getTransports().
        // backupEligible - The value of the BE flag in authData.
        // backupState - The value of the BS flag in authData.
        // The new credential record MAY also include the following OPTIONAL contents:
        // attestationObject - response.attestationObject
        // attestationClientDataJSON - response.clientDataJSON
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(authData);
        ArgumentNullException.ThrowIfNull(response);
        CredentialPublicKeyRecord publicKey;
        switch (authData.AttestedCredentialData.CredentialPublicKey.Kty)
        {
            case CoseKeyType.EC2:
                {
                    if (authData.AttestedCredentialData.CredentialPublicKey is not CoseEc2Key ec2Key)
                    {
                        throw new InvalidOperationException($"authData.attestedCredentialData.credentialPublicKey must contain a '{nameof(CoseEc2Key)}'");
                    }

                    var ec2Parameters = new CredentialPublicKeyEc2ParametersRecord(ec2Key.Crv, ec2Key.X, ec2Key.Y);
                    publicKey = new(ec2Key.Kty, ec2Key.Alg, null, ec2Parameters, null);
                    break;
                }
            case CoseKeyType.RSA:
                {
                    if (authData.AttestedCredentialData.CredentialPublicKey is not CoseRsaKey rsaKey)
                    {
                        throw new InvalidOperationException($"authData.attestedCredentialData.credentialPublicKey must contain a '{nameof(CoseRsaKey)}'");
                    }

                    var rsaParameters = new CredentialPublicKeyRsaParametersRecord(rsaKey.ModulusN, rsaKey.ExponentE);
                    publicKey = new(rsaKey.Kty, rsaKey.Alg, rsaParameters, null, null);
                    break;
                }
            case CoseKeyType.OKP:
                {
                    if (authData.AttestedCredentialData.CredentialPublicKey is not CoseOkpKey okpKey)
                    {
                        throw new InvalidOperationException($"authData.attestedCredentialData.credentialPublicKey must contain a '{nameof(CoseOkpKey)}'");
                    }

                    var okpParameters = new CredentialPublicKeyOkpParametersRecord(okpKey.Crv, okpKey.X);
                    publicKey = new(okpKey.Kty, okpKey.Alg, null, null, okpParameters);
                    break;
                }
            default:
                throw new InvalidOperationException("Unknown kty in authData.attestedCredentialData.credentialPublicKey");
        }


        var credentialRecord = new CredentialRecord(
            credential.Type,
            credential.RawId,
            publicKey,
            authData.SignCount,
            Array.Empty<AuthenticatorTransport>(),
            uvInitialized,
            backupEligible,
            backupState,
            response.AttestationObject,
            response.ClientDataJson);
        return credentialRecord;
    }

    /// <summary>
    ///     Creates a <see cref="UserCredentialRecord" />, which is the final artifact of the registration ceremony.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="registrationCeremonyParameters">Registration ceremony parameters.</param>
    /// <param name="request">Request containing parameters for completing the registration ceremony.</param>
    /// <param name="credentialRecord"><see cref="CredentialRecord" /> that stores the properties of the registered public key.</param>
    /// <param name="attestationObject">Decoded <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-object">attestation object</a>.</param>
    /// <param name="authData">Decoded value of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data (authData)</a>.</param>
    /// <param name="attStmt">Decoded value of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement (attStmt)</a>.</param>
    /// <param name="verifiedAttestationStatement">Verified value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement (attStmt)</a>.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>Instance of <see cref="UserCredentialRecord" />.</returns>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    /// <remarks>
    ///     This method is mostly made to allow the override of any properties of the resulting <see cref="UserCredentialRecord" /> before it is saved to the database.
    ///     For example, you can set the description of the registering public key depending on the type of attestation.
    ///     The asynchronous signature of this method is made for flexibility.
    ///     The saving of the <see cref="UserCredentialRecord" /> itself is performed in the next step.
    ///     Please don't save it to the database in this method.
    /// </remarks>
    protected virtual Task<UserCredentialRecord> CreateUserCredentialRecordAsync(
        TContext context,
        RegistrationCeremonyParameters registrationCeremonyParameters,
        CompleteRegistrationCeremonyRequest request,
        CredentialRecord credentialRecord,
        AttestationObject attestationObject,
        AttestedAuthenticatorData authData,
        AbstractAttestationStatement attStmt,
        VerifiedAttestationStatement verifiedAttestationStatement,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(registrationCeremonyParameters);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(credentialRecord);
        ArgumentNullException.ThrowIfNull(attestationObject);
        ArgumentNullException.ThrowIfNull(authData);
        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(verifiedAttestationStatement);
        var result = new UserCredentialRecord(
            registrationCeremonyParameters.Options.User.Id,
            registrationCeremonyParameters.ExpectedRp.RpId,
            request.Description,
            credentialRecord);
        return Task.FromResult(result);
    }
}

/// <summary>
///     Extension method for logging the registration ceremony.
/// </summary>
public static partial class DefaultRegistrationCeremonyServiceLoggingExtensions
{
    private static readonly Func<ILogger, string, IDisposable?> BeginCompleteRegistrationCeremonyScopeDelegate = LoggerMessage.DefineScope<string>(
        "Completion of registration ceremony with Id: {RegistrationCeremonyId}");

    /// <summary>
    ///     Creates a logging scope, within which the start of the registration ceremony will be handled.
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="registrationCeremonyId">Unique identifier of the registration ceremony.</param>
    /// <returns>A logging scope, in the form of an IDisposable object, the Dispose of which signifies the end of the scope's operation.</returns>
    public static IDisposable? BeginCompleteRegistrationCeremonyScope(
        this ILogger logger,
        string registrationCeremonyId)
    {
        return BeginCompleteRegistrationCeremonyScopeDelegate(logger, registrationCeremonyId);
    }

    /// <summary>
    ///     Registration ceremony not found.
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Registration ceremony not found")]
    public static partial void RegistrationCeremonyNotFound(this ILogger logger);

    /// <summary>
    ///     Failed to decode RegistrationResponseJSON
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode RegistrationResponseJSON")]
    public static partial void FailedToDecodeRegistrationResponseJson(this ILogger logger);

    /// <summary>
    ///     Failed to decode 'clientData'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode 'clientData'")]
    public static partial void FailedToDecodeClientData(this ILogger logger);

    /// <summary>
    ///     The 'clientData.type' is incorrect, as it expected 'webauthn.create' but received '{ClientDataType}'
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="clientDataType">The received 'clientData.type' value.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'clientData.type' is incorrect, as it expected 'webauthn.create' but received '{ClientDataType}'")]
    public static partial void IncorrectClientDataType(this ILogger logger, string clientDataType);

    /// <summary>
    ///     The challenge in the registration completion request doesn't match the one generated for this registration ceremony
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The challenge in the registration completion request doesn't match the one generated for this registration ceremony")]
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
    ///     Failed to perform CBOR decoding of the AttestationObject
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to perform CBOR decoding of the AttestationObject")]
    public static partial void AttestationObjectDecodeFailed(this ILogger logger);

    /// <summary>
    ///     'authData' must be present in the attestationObject for the registration ceremony, but it is null
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'authData' must be present in the attestationObject for the registration ceremony, but it is null")]
    public static partial void NullAuthDataForRegistration(this ILogger logger);

    /// <summary>
    ///     Failed to decode 'authData' from 'attestationObject'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode 'authData' from 'attestationObject'")]
    public static partial void FailedToDecodeAuthData(this ILogger logger);

    /// <summary>
    ///     Failed to decode 'attStmt' from 'attestationObject'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode 'attStmt' from 'attestationObject'")]
    public static partial void FailedToDecodeAttStmt(this ILogger logger);

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
    ///     'attestedCredentialData' is required for the registration ceremony, but it is null
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'attestedCredentialData' is required for the registration ceremony, but it is null")]
    public static partial void AttestedCredentialDataIsNull(this ILogger logger);

    /// <summary>
    ///     'alg' parameter in authData doesn't match with any in 'options.pubKeyCredParams'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'alg' parameter in authData doesn't match with any in 'options.pubKeyCredParams'")]
    public static partial void AuthDataAlgDoesntMatchPubKeyCredParams(this ILogger logger);

    /// <summary>
    ///     'attStmt' is invalid, failing to convey a valid attestation signature using 'fmt''s verification procedure with given 'authData' and 'hash'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'attStmt' is invalid, failing to convey a valid attestation signature using 'fmt''s verification procedure with given 'authData' and 'hash'")]
    public static partial void InvalidAttStmt(this ILogger logger);

    /// <summary>
    ///     A 'None' attestation has been provided, but the Relying Party policy does not permit 'None' attestations
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "A 'None' attestation has been provided, but the Relying Party policy does not permit 'None' attestations")]
    public static partial void NoneAttestationDisallowed(this ILogger logger);

    /// <summary>
    ///     A 'Self' attestation has been provided, but the Relying Party policy does not permit 'Self' attestations
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "A 'Self' attestation has been provided, but the Relying Party policy does not permit 'Self' attestations")]
    public static partial void SelfAttestationDisallowed(this ILogger logger);

    /// <summary>
    ///     Attestation Statement trustworthy check failed
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Attestation Statement trustworthy check failed")]
    public static partial void AttestationTrustPathIsInvalid(this ILogger logger);

    /// <summary>
    ///     CredentialId in AttestedCredentialData should be less or equal to 1023 bytes
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "CredentialId in AttestedCredentialData should be less or equal to 1023 bytes")]
    public static partial void CredentialIdIsTooBig(this ILogger logger);

    /// <summary>
    ///     CredentialId already associated with different user
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "CredentialId already associated with different user")]
    public static partial void CredentialIdExist(this ILogger logger);
}
