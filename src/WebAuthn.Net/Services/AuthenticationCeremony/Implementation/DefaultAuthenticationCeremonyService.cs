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
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Enums;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.CreateOptions;
using WebAuthn.Net.Models.Protocol.Enums;
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
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Static;
using WebAuthn.Net.Storage.AuthenticationCeremony;
using WebAuthn.Net.Storage.AuthenticationCeremony.Models;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.Credential.Models;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Implementation;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultAuthenticationCeremonyService<TContext> : IAuthenticationCeremonyService
    where TContext : class, IWebAuthnContext
{
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
        Logger = logger;
    }

    protected IOptionsMonitor<WebAuthnOptions> Options { get; }
    protected IWebAuthnContextFactory<TContext> ContextFactory { get; }
    protected IRelyingPartyIdProvider RpIdProvider { get; }
    protected IRelyingPartyOriginProvider RpOriginProvider { get; }
    protected IChallengeGenerator ChallengeGenerator { get; }
    protected ITimeProvider TimeProvider { get; }
    protected IPublicKeyCredentialRequestOptionsEncoder PublicKeyCredentialRequestOptionsEncoder { get; }
    protected ICredentialStorage<TContext> CredentialStorage { get; }
    protected IAuthenticationCeremonyStorage<TContext> CeremonyStorage { get; }
    protected IAuthenticationResponseDecoder AuthenticationResponseDecoder { get; }
    protected IClientDataDecoder ClientDataDecoder { get; }
    protected IAttestationObjectDecoder AttestationObjectDecoder { get; }
    protected IAuthenticatorDataDecoder AuthenticatorDataDecoder { get; }
    protected IAttestationStatementDecoder AttestationStatementDecoder { get; }
    protected IAttestationStatementVerifier<TContext> AttestationStatementVerifier { get; }
    protected IAttestationTrustPathValidator AttestationTrustPathValidator { get; }
    protected IDigitalSignatureVerifier SignatureVerifier { get; }
    protected ILogger<DefaultAuthenticationCeremonyService<TContext>> Logger { get; }

    public async Task<BeginAuthenticationCeremonyResult> BeginCeremonyAsync(
        HttpContext httpContext,
        BeginAuthenticationCeremonyRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        await using var context = await ContextFactory.CreateAsync(
            httpContext,
            WebAuthnOperation.BeginAuthenticationCeremony,
            cancellationToken);
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
        var expiresAt = ComputeExpiresAtUtc(createdAt, timeout);
        var options = ToPublicKeyCredentialRequestOptions(request, timeout, rpId, challenge, credentialsToInclude);
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
        return result;
    }

    public async Task<CompleteAuthenticationCeremonyResult> CompleteCeremonyAsync(
        HttpContext httpContext,
        CompleteAuthenticationCeremonyRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        using (Logger.BeginCompleteAuthenticationCeremonyScope(request.AuthenticationCeremonyId))
        await using (var context = await ContextFactory.CreateAsync(httpContext, WebAuthnOperation.CompleteAuthenticationCeremony, cancellationToken))
        {
            var authenticationCeremonyOptions = await CeremonyStorage.FindAsync(
                context,
                request.AuthenticationCeremonyId,
                cancellationToken);
            if (authenticationCeremonyOptions is null)
            {
                Logger.AuthenticationCeremonyNotFound();
                return CompleteAuthenticationCeremonyResult.Fail();
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
                return CompleteAuthenticationCeremonyResult.Fail();
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
                    return CompleteAuthenticationCeremonyResult.Fail();
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
                    return CompleteAuthenticationCeremonyResult.Fail();
                }

                if (!dbCredential.ContainsCredentialThatBelongsTo(
                        authenticationCeremonyOptions.ExpectedRp.RpId,
                        authenticationCeremonyOptions.UserHandle,
                        credential.RawId))
                {
                    Logger.CredentialMismatch();
                    return CompleteAuthenticationCeremonyResult.Fail();
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
                        return CompleteAuthenticationCeremonyResult.Fail();
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
                    return CompleteAuthenticationCeremonyResult.Fail();
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
                    return CompleteAuthenticationCeremonyResult.Fail();
                }

                if (!dbCredential.ContainsCredentialThatBelongsTo(
                        authenticationCeremonyOptions.ExpectedRp.RpId,
                        response.UserHandle,
                        credential.RawId))
                {
                    Logger.CredentialMismatch();
                    return CompleteAuthenticationCeremonyResult.Fail();
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
                return CompleteAuthenticationCeremonyResult.Fail();
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
                return CompleteAuthenticationCeremonyResult.Fail();
            }

            // ReSharper disable once InconsistentNaming
            var C = clientDataResult.Ok;

            // 12. Verify that the value of C.type is the string 'webauthn.get'.
            if (C.Type is not "webauthn.get")
            {
                Logger.IncorrectClientDataType(C.Type);
                return CompleteAuthenticationCeremonyResult.Fail();
            }

            // 13. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
            if (!string.Equals(C.Challenge, Base64Url.Encode(options.Challenge), StringComparison.Ordinal))
            {
                Logger.ChallengeMismatch();
                return CompleteAuthenticationCeremonyResult.Fail();
            }

            // 14. Verify that the value of C.origin is an origin expected by the Relying Party. See §13.4.9 Validating the origin of a credential for guidance.
            var allowedOrigin = authenticationCeremonyOptions.ExpectedRp.Origins.FirstOrDefault(x => string.Equals(x, C.Origin, StringComparison.Ordinal));
            if (allowedOrigin is null)
            {
                Logger.InvalidOrigin(C.Origin);
                return CompleteAuthenticationCeremonyResult.Fail();
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
                        return CompleteAuthenticationCeremonyResult.Fail();
                    }
                }
                else
                {
                    if (!string.Equals(allowedOrigin, C.TopOrigin, StringComparison.Ordinal))
                    {
                        Logger.InvalidTopOrigin(C.TopOrigin);
                        return CompleteAuthenticationCeremonyResult.Fail();
                    }
                }
            }

            // 16. Verify that the 'rpIdHash' in 'authData' is the SHA-256 hash of the RP ID expected by the Relying Party.
            var authDataRpIdHash = authData.RpIdHash;
            var expectedRpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(authenticationCeremonyOptions.ExpectedRp.RpId));
            if (!authDataRpIdHash.AsSpan().SequenceEqual(expectedRpIdHash.AsSpan()))
            {
                Logger.RpIdHashMismatch();
                return CompleteAuthenticationCeremonyResult.Fail();
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
                    return CompleteAuthenticationCeremonyResult.Fail();
                }

                // 18. Determine whether user verification is required for this assertion.
                // User verification SHOULD be required if, and only if, options.userVerification is set to required.
                // If user verification was determined to be required, verify that the UV bit of the flags in authData is set.
                // Otherwise, ignore the value of the UV flag.
                uvInitialized = (authData.Flags & AuthenticatorDataFlags.UserVerified) is AuthenticatorDataFlags.UserVerified;
                if (userVerificationRequired && !uvInitialized.Value)
                {
                    Logger.UserVerificationBitNotSet();
                    return CompleteAuthenticationCeremonyResult.Fail();
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
                return CompleteAuthenticationCeremonyResult.Fail();
            }

            // Compare 'currentBe' and 'currentBs' with 'credentialRecord.backupEligible' and 'credentialRecord.backupState':
            // 20.1. If credentialRecord.backupEligible is set, verify that 'currentBe' is set.

            if (credentialRecord.BackupEligible)
            {
                if (!currentBe)
                {
                    Logger.BackupEligibleBitNotSet();
                    return CompleteAuthenticationCeremonyResult.Fail();
                }
            }

            // 20.2. If credentialRecord.backupEligible is not set, verify that 'currentBe' is not set.
            if (!credentialRecord.BackupEligible)
            {
                if (currentBe)
                {
                    Logger.BackupEligibleBitSet();
                    return CompleteAuthenticationCeremonyResult.Fail();
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
                return CompleteAuthenticationCeremonyResult.Fail();
            }

            if (!SignatureVerifier.IsValidCoseKeySign(credentialRecordPublicKey, dataToVerify, sig))
            {
                Logger.InvalidSignature();
                return CompleteAuthenticationCeremonyResult.Fail();
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
                        return CompleteAuthenticationCeremonyResult.Fail();
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
                    return CompleteAuthenticationCeremonyResult.Fail();
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
                    return CompleteAuthenticationCeremonyResult.Fail();
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
                credentialRecordUpdateResult.UpdatedCredentialRecord);
            var updated = await CredentialStorage.UpdateCredentialAsync(context, updatedCredential, cancellationToken);
            if (!updated)
            {
                Logger.CredentialStorageUpdateFailed();
                return CompleteAuthenticationCeremonyResult.Fail();
            }

            // 27. If all the above steps are successful, continue with the authentication ceremony as appropriate. Otherwise, fail the authentication ceremony.
            var result = CompleteAuthenticationCeremonyResult.Success(
                recommendedActions,
                credentialRecordUpdateResult.UvInitializedUpdated);
            await context.CommitAsync(cancellationToken);
            return result;
        }
    }

    protected virtual DateTimeOffset ComputeExpiresAtUtc(DateTimeOffset value, uint timeout)
    {
        var expiresAtMilliseconds = value.ToUnixTimeMilliseconds() + timeout;
        return DateTimeOffset.FromUnixTimeMilliseconds(expiresAtMilliseconds);
    }

    protected virtual uint GetTimeout(BeginAuthenticationCeremonyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Timeout.HasValue)
        {
            return request.Timeout.Value;
        }

        return Options.CurrentValue.AuthenticationCeremony.DefaultTimeout;
    }

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

        var newUvInitialized = old.UvInitialized;
        var uvInitializedUpdated = false;
        if (Options.CurrentValue.AuthenticationCeremony.AllowToUpdateUserUserVerifiedFlag)
        {
            if (!old.UvInitialized && uvInitialized.HasValue && uvInitialized.Value)
            {
                newUvInitialized = true;
                uvInitializedUpdated = true;
            }
        }

        var updatedCredentialRecord = new CredentialRecord(
            old.Type,
            old.Id,
            old.PublicKey,
            authDataSignCount,
            old.Transports,
            newUvInitialized,
            old.BackupEligible,
            currentBs,
            attestationObject,
            attestationClientDataJson);
        return new(updatedCredentialRecord, uvInitializedUpdated);
    }

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

    protected virtual byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }

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

            var resultKeysToExclude = new List<PublicKeyCredentialDescriptor>(options.ManuallySpecifiedKeysToInclude.Length);
            foreach (var existingKey in existingKeys)
            {
                var requestedKeyToExclude = options
                    .ManuallySpecifiedKeysToInclude
                    .FirstOrDefault(x => x.Type == existingKey.Type && x.Id.AsSpan().SequenceEqual(existingKey.Id));
                if (requestedKeyToExclude is not null)
                {
                    resultKeysToExclude.Add(requestedKeyToExclude);
                }
            }

            if (resultKeysToExclude.Count > 0)
            {
                return resultKeysToExclude.ToArray();
            }
        }

        return null;
    }

    protected virtual PublicKeyCredentialRequestOptions ToPublicKeyCredentialRequestOptions(
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

public static partial class DefaultAuthenticationCeremonyServiceLoggingExtensions
{
    private static readonly Func<ILogger, string, IDisposable?> BeginCompleteAuthenticationCeremonyScopeDelegate = LoggerMessage.DefineScope<string>(
        "Completion of registration ceremony with Id: {AuthenticationCeremonyId}");

    public static IDisposable? BeginCompleteAuthenticationCeremonyScope(
        this ILogger logger,
        string authenticationCeremonyId)
    {
        return BeginCompleteAuthenticationCeremonyScopeDelegate(logger, authenticationCeremonyId);
    }

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Authentication ceremony not found")]
    public static partial void AuthenticationCeremonyNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode AuthenticationResponseJSON")]
    public static partial void FailedToDecodeAuthenticationResponseJson(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The received credential.id is not included in the list specified in options.allowCredentials")]
    public static partial void InvalidCredentialId(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find an existing credential with the specified Id")]
    public static partial void CredentialNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The credential obtained from the storage does not match the parameters of the authentication ceremony")]
    public static partial void CredentialMismatch(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "response.userHandle does not equal the user handle of the user account")]
    public static partial void ResponseUserHandleMismatch(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "response.userHandle is not present")]
    public static partial void UserHandleNotPresentInResponse(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode response.AuthenticatorData")]
    public static partial void FailedToDecodeResponseAuthenticatorData(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode response.clientDataJSON")]
    public static partial void FailedToDecodeResponseClientDataJson(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'clientData.type' is incorrect, as it expected 'webauthn.get' but received '{ClientDataType}'")]
    public static partial void IncorrectClientDataType(this ILogger logger, string clientDataType);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The challenge in the authentication completion request doesn't match the one generated for this authentication ceremony")]
    public static partial void ChallengeMismatch(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Invalid value for origin: '{ClientDataOrigin}'")]
    public static partial void InvalidOrigin(this ILogger logger, string clientDataOrigin);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Invalid value for topOrigin: '{ClientDataTopOrigin}'")]
    public static partial void InvalidTopOrigin(this ILogger logger, string clientDataTopOrigin);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'rpIdHash' in 'authData' does not match the SHA-256 hash of the RP ID expected by the Relying Party")]
    public static partial void RpIdHashMismatch(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "User Present bit in 'authData.flags' isn't set")]
    public static partial void UserPresentBitNotSet(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "User Verification bit in 'authData.flags' is required, but not set")]
    public static partial void UserVerificationBitNotSet(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'authData.flags' contains an invalid combination of Backup Eligibility (BE) and Backup State (BS) flags")]
    public static partial void InvalidBeBsFlagsCombination(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Backup Eligible bit in 'authData.flags' is required, but not set")]
    public static partial void BackupEligibleBitNotSet(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Backup Eligible bit in 'authData.flags' is set, but it shouldn't be")]
    public static partial void BackupEligibleBitSet(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to transform the public key of the found credentialRecord into a CoseKey")]
    public static partial void FailedToTransformCredentialPublicKey(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Invalid signature")]
    public static partial void InvalidSignature(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The obtained signCount is less than or equal to the one that was saved earlier")]
    public static partial void AbortBySignCount(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to perform CBOR decoding of the AttestationObject")]
    public static partial void AttestationObjectDecodeFailed(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "AttestationObject is invalid")]
    public static partial void AttestationObjectVerificationFailed(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to update user credential record")]
    public static partial void CredentialStorageUpdateFailed(this ILogger logger);
}
