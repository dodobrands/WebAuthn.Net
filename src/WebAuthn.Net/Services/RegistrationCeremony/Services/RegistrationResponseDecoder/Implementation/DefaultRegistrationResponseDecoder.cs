using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Json;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.RegistrationResponseDecoder.Implementation;

[SuppressMessage("ReSharper", "StaticMemberInGenericType")]
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultRegistrationResponseDecoder<TContext> : IRegistrationResponseDecoder<TContext>
    where TContext : class, IWebAuthnContext
{
    protected static readonly EnumMemberAttributeMapper<AuthenticatorTransport> TransportMapper = new();
    protected static readonly EnumMemberAttributeMapper<AuthenticatorAttachment> AttachmentMapper = new();
    protected static readonly EnumMemberAttributeMapper<PublicKeyCredentialType> TypeMapper = new();

    public virtual async Task<Result<RegistrationResponse>> DecodeAsync(
        TContext context,
        RegistrationResponseJSON registrationResponse,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (registrationResponse is null)
        {
            return Result<RegistrationResponse>.Fail();
        }

        var id = WebEncoders.Base64UrlDecode(registrationResponse.Id);
        var rawId = WebEncoders.Base64UrlDecode(registrationResponse.RawId);
        var responseResult = await DecodeAttestationResponseAsync(context, registrationResponse.Response, cancellationToken);
        if (responseResult.HasError)
        {
            return Result<RegistrationResponse>.Fail();
        }

        AuthenticatorAttachment? authenticatorAttachment = null;
        if (registrationResponse.AuthenticatorAttachment is not null)
        {
            if (!AttachmentMapper.TryGetEnumFromString(registrationResponse.AuthenticatorAttachment, out var attachment))
            {
                return Result<RegistrationResponse>.Fail();
            }

            authenticatorAttachment = attachment.Value;
        }

        AuthenticationExtensionsClientOutputs? clientExtensionResults = null;
        if (registrationResponse.ClientExtensionResults is not null)
        {
            clientExtensionResults = new();
        }

        if (!TypeMapper.TryGetEnumFromString(registrationResponse.Type, out var type))
        {
            return Result<RegistrationResponse>.Fail();
        }

        var result = new RegistrationResponse(
            id,
            rawId,
            responseResult.Ok,
            authenticatorAttachment,
            clientExtensionResults,
            type.Value);
        return Result<RegistrationResponse>.Success(result);
    }

    protected virtual Task<Result<AuthenticatorAttestationResponse>> DecodeAttestationResponseAsync(
        TContext context,
        AuthenticatorAttestationResponseJSON attestationResponseJson,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(attestationResponseJson);
        cancellationToken.ThrowIfCancellationRequested();
        var clientDataJson = WebEncoders.Base64UrlDecode(attestationResponseJson.ClientDataJson);
        byte[]? authenticatorData = null;
        if (attestationResponseJson.AuthenticatorData is not null)
        {
            authenticatorData = WebEncoders.Base64UrlDecode(attestationResponseJson.AuthenticatorData);
        }

        AuthenticatorTransport[]? transports = null;
        if (attestationResponseJson.Transports is not null)
        {
            transports = new AuthenticatorTransport[attestationResponseJson.Transports.Length];
            for (var i = 0; i < attestationResponseJson.Transports.Length; i++)
            {
                if (!TransportMapper.TryGetEnumFromString(attestationResponseJson.Transports[i], out var transport))
                {
                    return Task.FromResult(Result<AuthenticatorAttestationResponse>.Fail());
                }

                transports[i] = transport.Value;
            }
        }

        byte[]? publicKey = null;
        if (attestationResponseJson.PublicKey is not null)
        {
            publicKey = WebEncoders.Base64UrlDecode(attestationResponseJson.PublicKey);
        }

        CoseAlgorithm? publicKeyAlgorithm = null;
        if (attestationResponseJson.PublicKeyAlgorithm.HasValue)
        {
            var castedAlgorithm = (CoseAlgorithm) attestationResponseJson.PublicKeyAlgorithm.Value;
            if (!Enum.IsDefined(castedAlgorithm))
            {
                return Task.FromResult(Result<AuthenticatorAttestationResponse>.Fail());
            }

            publicKeyAlgorithm = castedAlgorithm;
        }

        var attestationObject = WebEncoders.Base64UrlDecode(attestationResponseJson.AttestationObject);
        var result = new AuthenticatorAttestationResponse(
            clientDataJson,
            authenticatorData,
            transports,
            publicKey,
            publicKeyAlgorithm,
            attestationObject);
        return Task.FromResult(Result<AuthenticatorAttestationResponse>.Success(result));
    }
}
