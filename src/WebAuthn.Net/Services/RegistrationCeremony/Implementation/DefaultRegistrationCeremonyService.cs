using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Extensions;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Services.RegistrationCeremony.Models;
using WebAuthn.Net.Services.RelyingPartyOrigin;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject;
using WebAuthn.Net.Services.TimeProvider;
using WebAuthn.Net.Storage.Operations;
using WebAuthn.Net.Storage.Operations.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation;

public class DefaultRegistrationCeremonyService<TContext> : IRegistrationCeremonyService
    where TContext : class, IWebAuthnContext
{
    private readonly IAttestationObjectDecoder _attestationObjectDecoder;
    private readonly IChallengeGenerator _challengeGenerator;
    private readonly IClientDataDecoder _clientDataDecoder;
    private readonly IWebAuthnContextFactory<TContext> _contextFactory;
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
        IAttestationObjectDecoder attestationObjectDecoder)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(contextFactory);
        ArgumentNullException.ThrowIfNull(challengeGenerator);
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(clientDataDecoder);
        ArgumentNullException.ThrowIfNull(originProvider);
        ArgumentNullException.ThrowIfNull(attestationObjectDecoder);
        _contextFactory = contextFactory;
        _challengeGenerator = challengeGenerator;
        _storage = storage;
        _timeProvider = timeProvider;
        _clientDataDecoder = clientDataDecoder;
        _originProvider = originProvider;
        _attestationObjectDecoder = attestationObjectDecoder;
        _options = options;
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
        var createdAt = _timeProvider.GetUtcDateTime();
        var expiresAt = createdAt.ComputeExpiresAtUtc(request.Timeout);
        var saveRequest = ConvertToSaveRequest(challenge, request, credentialsToExclude, createdAt, expiresAt);
        var options = ConvertToOptions(request, challenge, credentialsToExclude);
        var ceremonyId = await _storage.SaveRegistrationCeremonyOptionsAsync(context, saveRequest, cancellationToken);
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
        await using var context = await _contextFactory.CreateAsync(httpContext, cancellationToken);
        var options = await _storage.FindRegistrationCeremonyOptionsAsync(context, request.RegistrationCeremonyId, cancellationToken);
        if (options is null)
        {
            return Result<CompleteCeremonyResult>.Failed("Can't find existing registration ceremony");
        }

        // https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
        // 1. Let options be a new PublicKeyCredentialCreationOptions structure configured to the Relying Party's needs for the ceremony.
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
            return Result<CompleteCeremonyResult>.Failed(clientDataResult.Error);
        }

        // ReSharper disable once InconsistentNaming
        var C = clientDataResult.Ok;
        // 7. Verify that the value of C.type is webauthn.create.
        if (C.Type is not "webauthn.create")
        {
            return Result<CompleteCeremonyResult>.Failed($"AttestationResponse type must be 'webauthn.create', but was {C.Type}");
        }

        // 8. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
        if (!string.Equals(C.Challenge, WebEncoders.Base64UrlEncode(options.Challenge), StringComparison.Ordinal))
        {
            return Result<CompleteCeremonyResult>.Failed($"AttestationResponse type must be 'webauthn.create', but was {C.Type}");
        }

        // 9. Verify that the value of C.origin matches the Relying Party's origin.
        var relyingPartyOrigin = await _originProvider.GetAsync(context, cancellationToken);
        if (!string.Equals(C.Origin, relyingPartyOrigin, StringComparison.Ordinal))
        {
            return Result<CompleteCeremonyResult>.Failed($"The value of origin in clientData: '{C.Origin}' does not match the relying party's origin: '{relyingPartyOrigin}'");
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
            return Result<CompleteCeremonyResult>.Failed(attestationObjectResult.Error);
        }

        var attestationObject = attestationObjectResult.Ok;

        // var fmt = (string?) null;
        // var authData = (string?) null;
        // var attStmt = (string?) null;


        throw new NotImplementedException();
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

    private static RegistrationCeremonyOptionsSaveRequest ConvertToSaveRequest(
        byte[] challenge,
        BeginCeremonyRequest request,
        PublicKeyCredentialDescriptor[]? credentialsToExclude,
        DateTimeOffset createdAt,
        DateTimeOffset? expiresAt)
    {
        return new(
            challenge,
            request.Rp,
            request.User,
            request.PubKeyCredParams,
            request.Timeout,
            credentialsToExclude,
            request.AuthenticatorSelection,
            request.Attestation,
            createdAt,
            expiresAt);
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
