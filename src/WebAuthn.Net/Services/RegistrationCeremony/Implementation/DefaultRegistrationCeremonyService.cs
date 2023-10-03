using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Extensions;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.ClientDataDecoder.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Models;
using WebAuthn.Net.Services.RelyingPartyOrigin;
using WebAuthn.Net.Services.TimeProvider;
using WebAuthn.Net.Storage.Operations;
using WebAuthn.Net.Storage.Operations.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation;

public class DefaultRegistrationCeremonyService<TContext> : IRegistrationCeremonyService
    where TContext : class, IWebAuthnContext
{
    private readonly IAttestationObjectDecoder _attestationObjectDecoder;
    private readonly IAttestationStatementVerifier<TContext> _attestationStatementVerifier;
    private readonly IChallengeGenerator _challengeGenerator;
    private readonly IClientDataDecoder _clientDataDecoder;
    private readonly IWebAuthnContextFactory<TContext> _contextFactory;
    private readonly ILogger<DefaultRegistrationCeremonyService<TContext>> _logger;
    private readonly WebAuthnOptions _options;
    private readonly IRelyingPartyOriginProvider<TContext> _originProvider;
    private readonly IOperationalStorage<TContext> _storage;
    private readonly ITimeProvider _timeProvider;

    public DefaultRegistrationCeremonyService(
        WebAuthnOptions options,
        IWebAuthnContextFactory<TContext> contextFactory,
        IChallengeGenerator challengeGenerator,
        IOperationalStorage<TContext> storage,
        ITimeProvider timeProvider,
        IClientDataDecoder clientDataDecoder,
        IRelyingPartyOriginProvider<TContext> originProvider,
        IAttestationObjectDecoder attestationObjectDecoder,
        IAttestationStatementVerifier<TContext> attestationStatementVerifier,
        ILogger<DefaultRegistrationCeremonyService<TContext>> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(contextFactory);
        ArgumentNullException.ThrowIfNull(challengeGenerator);
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(clientDataDecoder);
        ArgumentNullException.ThrowIfNull(originProvider);
        ArgumentNullException.ThrowIfNull(attestationObjectDecoder);
        ArgumentNullException.ThrowIfNull(attestationStatementVerifier);
        ArgumentNullException.ThrowIfNull(logger);
        _options = options;
        _contextFactory = contextFactory;
        _challengeGenerator = challengeGenerator;
        _storage = storage;
        _timeProvider = timeProvider;
        _clientDataDecoder = clientDataDecoder;
        _originProvider = originProvider;
        _attestationObjectDecoder = attestationObjectDecoder;
        _attestationStatementVerifier = attestationStatementVerifier;
        _logger = logger;
    }

    public async Task<BeginCeremonyResult> BeginCeremonyAsync(
        HttpContext httpContext,
        BeginCeremonyRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        await using var context = await _contextFactory.CreateAsync(httpContext, cancellationToken);
        var challenge = _challengeGenerator.GenerateChallenge(request.ChallengeSize);
        var credentialsToExclude = await GetCredentialsToExcludeAsync(context, request.Rp, request.User, request.ExcludeCredentials, cancellationToken);
        var createdAt = _timeProvider.GetRoundUtcDateTime();
        var expiresAt = createdAt.ComputeExpiresAtUtc(request.Timeout);
        var options = ConvertToOptions(request, challenge, credentialsToExclude);
        var registrationCeremonyOptions = new RegistrationCeremonyOptions(options, createdAt, expiresAt);
        var ceremonyId = await _storage.SaveRegistrationCeremonyOptionsAsync(context, registrationCeremonyOptions, cancellationToken);
        await context.CommitAsync(cancellationToken);
        return new(options, ceremonyId);
    }

    public async Task<Result<CompleteCeremonyResult>> CompleteCeremonyAsync(
        HttpContext httpContext,
        CompleteCeremonyRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        using (_logger.BeginCompleteRegistrationCeremonyScope(request.RegistrationCeremonyId))
        await using (var context = await _contextFactory.CreateAsync(httpContext, cancellationToken))
        {
            var registrationCeremonyOptions = await _storage.FindRegistrationCeremonyOptionsAsync(context, request.RegistrationCeremonyId, cancellationToken);
            if (registrationCeremonyOptions is null)
            {
                _logger.RegistrationCeremonyNotFound();
                return Result<CompleteCeremonyResult>.Fail();
            }

            // https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
            // 1. Let options be a new PublicKeyCredentialCreationOptions structure configured to the Relying Party's needs for the ceremony.
            var options = registrationCeremonyOptions.Options.PublicKey;
            // 2. Call navigator.credentials.create() and pass options as the publicKey option. Let credential be the result
            // of the successfully resolved promise. If the promise is rejected, abort the ceremony with a user-visible error,
            // or otherwise guide the user experience as might be determinable from the context available in the rejected promise.
            // For example if the promise is rejected with an error code equivalent to "InvalidStateError",
            // the user might be instructed to use a different authenticator.
            // For information on different error contexts and the circumstances leading to them, see § .3.2 The authenticatorMakeCredential Operation.
            // 3. Let response be credential.response. If response is not an instance of AuthenticatorAttestationResponse,
            // abort the ceremony with a user-visible error.
            // 4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().
            // 5. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
            // Note: Using any implementation of UTF-8 decode is acceptable as long as it yields the same result as that yielded by the UTF-8 decode algorithm.
            // In particular, any leading byte order mark (BOM) MUST be stripped.
            // 6. Let C, the client data claimed as collected during the credential creation,
            // be the result of running an implementation-specific JSON parser on JSONtext.
            // Note: C may be any implementation-specific data structure representation, as long as C’s components are referenceable, as required by this algorithm.
            var clientDataResult = _clientDataDecoder.Decode(request.Credential.Response.ClientDataJson);
            if (clientDataResult.HasError)
            {
                _logger.FailedToDecodeClientData();
                return Result<CompleteCeremonyResult>.Fail();
            }

            // ReSharper disable once InconsistentNaming
            var C = clientDataResult.Ok;

            // 7. Verify that the value of C.type is webauthn.create.
            if (C.Type is not "webauthn.create")
            {
                _logger.IncorrectClientDataType(C.Type);
                return Result<CompleteCeremonyResult>.Fail();
            }

            // 8. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
            if (!string.Equals(C.Challenge, WebEncoders.Base64UrlEncode(options.Challenge), StringComparison.Ordinal))
            {
                _logger.ChallengeMismatch();
                return Result<CompleteCeremonyResult>.Fail();
            }

            // 9. Verify that the value of C.origin matches the Relying Party's origin.
            var relyingPartyOrigin = await _originProvider.GetAsync(context, cancellationToken);
            if (!string.Equals(C.Origin, relyingPartyOrigin, StringComparison.Ordinal))
            {
                _logger.OriginMismatch(C.Origin, relyingPartyOrigin);
                return Result<CompleteCeremonyResult>.Fail();
            }
            // 10. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection
            // over which the assertion was obtained. If Token Binding was used on that TLS connection, also verify that
            // C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
            // https://w3c.github.io/webauthn/#collectedclientdata-tokenbinding
            // Web Authentication: An API for accessing Public Key Credentials Level 3. Editor’s Draft, 12 September 2023 - § 5.8.1. Client Data Used in WebAuthn Signatures
            // NOTE: While Token Binding was present in Level 1 and Level 2 of WebAuthn, its use is not expected in Level 3.
            // The tokenBinding field is reserved so that it will not be reused for a different purpose.
            // -----
            // skip token binding

            // 11. Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.
            var hash = SHA256.HashData(request.Credential.Response.ClientDataJson);

            // 12. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure
            // to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.
            var attestationObjectResult = _attestationObjectDecoder.Decode(request.Credential.Response.AttestationObject);
            if (attestationObjectResult.HasError)
            {
                return Result<CompleteCeremonyResult>.Fail();
            }

            var fmt = attestationObjectResult.Ok.Fmt;
            var authData = attestationObjectResult.Ok.AuthData;
            var attStmt = attestationObjectResult.Ok.AttStmt;

            // 13. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
            if (!authData.RpIdHash.AsSpan().SequenceEqual(SHA256.HashData(Encoding.UTF8.GetBytes(options.Rp.Id)).AsSpan()))
            {
                _logger.RpIdHashMismatch();
                return Result<CompleteCeremonyResult>.Fail();
            }

            // 14. Verify that the User Present bit of the flags in authData is set.
            if (!authData.Flags.Contains(AuthenticatorDataFlags.UserPresent))
            {
                _logger.UserPresentBitNotSet();
                return Result<CompleteCeremonyResult>.Fail();
            }

            // 15. If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.
            if (options.AuthenticatorSelection?.UserVerification == UserVerificationRequirement.Required && !authData.Flags.Contains(AuthenticatorDataFlags.UserVerified))
            {
                _logger.UserVerificationBitNotSet();
                return Result<CompleteCeremonyResult>.Fail();
            }

            // 16. Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.
            if (!authData.Flags.Contains(AuthenticatorDataFlags.AttestedCredentialData))
            {
                _logger.AttestedCredentialDataIncludedBitNotSet();
                return Result<CompleteCeremonyResult>.Fail();
            }

            if (authData.AttestedCredentialData is null)
            {
                _logger.AttestedCredentialDataIsNull();
                return Result<CompleteCeremonyResult>.Fail();
            }

            var expectedAlgorithms = options.PubKeyCredParams.Select(x => x.Alg).ToHashSet();
            if (!expectedAlgorithms.Contains(authData.AttestedCredentialData.CredentialPublicKey.Alg))
            {
                _logger.AuthDataAlgDoesntMatchPubKeyCredParams();
                return Result<CompleteCeremonyResult>.Fail();
            }
            // 17. Verify that the values of the client extension outputs in clientExtensionResults
            // and the authenticator extension outputs in the extensions in authData are as expected,
            // considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party
            // regarding unsolicited extensions, i.e., those that were not specified as part of options.extensions.
            // In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
            // -----
            // skip extensions

            // 18. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt
            // against the set of supported WebAuthn Attestation Statement Format Identifier values.
            // An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is
            // maintained in the IANA "WebAuthn Attestation Statement Format Identifiers" registry [IANA-WebAuthn-Registries] established by [RFC8809].
            // -----
            // already verified

            // 19. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature,
            // by using the attestation statement format fmt’s verification procedure given attStmt, authData and hash.
            // Note: Each attestation statement format specifies its own verification procedure.
            // See § 8 Defined Attestation Statement Formats for the initially-defined formats, and [IANA-WebAuthn-Registries] for the up-to-date list.

            // var attStmtIsValid = await _attestationStatementVerifier.VerifyAttestationStatementAsync(
            //     context,
            //     fmt,
            //     attStmt,
            //     new(authData.RpIdHash, authData.Flags, authData.SignCount, authData.AttestedCredentialData),
            //     hash,
            //     cancellationToken);
            // if (!attStmtIsValid)
            // {
            //     _logger.InvalidAttStmt();
            //     return Result<CompleteCeremonyResult>.Fail();
            // }

            throw new NotImplementedException();
        }
    }

    private async Task<PublicKeyCredentialDescriptor[]?> GetCredentialsToExcludeAsync(
        TContext context,
        PublicKeyCredentialRpEntity rp,
        PublicKeyCredentialUserEntity user,
        ExcludeCredentialsOptions options,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (options.ExcludeAllExistingKeys)
        {
            var existingKeys = await _storage.GetExistingCredentialsAsync(context, rp, user, cancellationToken);
            if (existingKeys?.Length > 0)
            {
                return existingKeys;
            }

            return null;
        }

        if (options.ExcludeSpecificKeys)
        {
            var existingKeys = await _storage.GetExistingCredentialsAsync(context, rp, user, cancellationToken);
            if ((existingKeys?.Length > 0) is not true)
            {
                return null;
            }

            var resultKeysToExclude = new List<PublicKeyCredentialDescriptor>(options.SpecificKeysToExclude.Length);
            foreach (var existingKey in existingKeys)
            {
                var requestedKeyToExclude = options
                    .SpecificKeysToExclude
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

    private static CredentialCreationOptions ConvertToOptions(
        BeginCeremonyRequest request,
        byte[] challenge,
        PublicKeyCredentialDescriptor[]? excludeCredentials)
    {
        return new(new(
            request.Rp,
            request.User,
            challenge,
            request.PubKeyCredParams,
            request.Timeout,
            excludeCredentials,
            request.AuthenticatorSelection,
            request.Attestation,
            null));
    }
}

public static partial class DefaultRegistrationCeremonyServiceLoggingExtensions
{
    private static readonly Func<ILogger, string, IDisposable?> CompleteRegistrationCeremony = LoggerMessage.DefineScope<string>(
        "Completion of registration ceremony with Id: {RegistrationCeremonyId}");

    public static IDisposable? BeginCompleteRegistrationCeremonyScope(
        this ILogger logger,
        string registrationCeremonyId)
    {
        return CompleteRegistrationCeremony(logger, registrationCeremonyId);
    }

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Registration ceremony not found")]
    public static partial void RegistrationCeremonyNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode 'clientData'")]
    public static partial void FailedToDecodeClientData(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'clientData.type' is incorrect, as it expected 'webauthn.create' but received '{ClientDataType}'")]
    public static partial void IncorrectClientDataType(this ILogger logger, string clientDataType);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The challenge in the registration completion request doesn't match the one generated for this registration ceremony")]
    public static partial void ChallengeMismatch(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The value of clientData.origin: '{ClientDataOrigin}' doesn't match the relying party's origin: '{RelyingPartyOrigin}'")]
    public static partial void OriginMismatch(this ILogger logger, string clientDataOrigin, string relyingPartyOrigin);

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
        Message = "Attested Credential Data Included bit in 'authData.flags' is required, but not set")]
    public static partial void AttestedCredentialDataIncludedBitNotSet(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'attestedCredentialData' is required for the registration ceremony, but it is null")]
    public static partial void AttestedCredentialDataIsNull(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'alg' parameter in authData doesn't match with any in 'options.pubKeyCredParams'")]
    public static partial void AuthDataAlgDoesntMatchPubKeyCredParams(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "'attStmt' is invalid, failing to convey a valid attestation signature using 'fmt''s verification procedure with given 'authData' and 'hash'")]
    public static partial void InvalidAttStmt(this ILogger logger);
}
