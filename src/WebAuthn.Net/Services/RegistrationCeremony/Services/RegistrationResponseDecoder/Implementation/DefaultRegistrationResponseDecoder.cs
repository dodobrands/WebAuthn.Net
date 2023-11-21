using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.RegistrationResponseDecoder.Implementation;

[SuppressMessage("ReSharper", "StaticMemberInGenericType")]
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultRegistrationResponseDecoder : IRegistrationResponseDecoder
{
    public DefaultRegistrationResponseDecoder(
        IEnumMemberAttributeSerializer<AuthenticatorTransport> authenticatorTransportSerializer,
        IEnumMemberAttributeSerializer<AuthenticatorAttachment> authenticatorAttachmentSerializer,
        IEnumMemberAttributeSerializer<PublicKeyCredentialType> publicKeyCredentialTypeSerializer)
    {
        ArgumentNullException.ThrowIfNull(authenticatorTransportSerializer);
        ArgumentNullException.ThrowIfNull(authenticatorAttachmentSerializer);
        ArgumentNullException.ThrowIfNull(publicKeyCredentialTypeSerializer);
        AuthenticatorTransportSerializer = authenticatorTransportSerializer;
        AuthenticatorAttachmentSerializer = authenticatorAttachmentSerializer;
        PublicKeyCredentialTypeSerializer = publicKeyCredentialTypeSerializer;
    }

    protected IEnumMemberAttributeSerializer<AuthenticatorTransport> AuthenticatorTransportSerializer { get; }
    protected IEnumMemberAttributeSerializer<AuthenticatorAttachment> AuthenticatorAttachmentSerializer { get; }
    protected IEnumMemberAttributeSerializer<PublicKeyCredentialType> PublicKeyCredentialTypeSerializer { get; }

    public Result<RegistrationResponse> Decode(RegistrationResponseJSON registrationResponse)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (registrationResponse is null)
        {
            return Result<RegistrationResponse>.Fail();
        }

        if (!Base64Url.TryDecode(registrationResponse.Id, out var id))
        {
            return Result<RegistrationResponse>.Fail();
        }

        if (!Base64Url.TryDecode(registrationResponse.RawId, out var rawId))
        {
            return Result<RegistrationResponse>.Fail();
        }

        var responseResult = DecodeAttestationResponse(registrationResponse.Response);
        if (responseResult.HasError)
        {
            return Result<RegistrationResponse>.Fail();
        }

        AuthenticatorAttachment? authenticatorAttachment = null;
        if (registrationResponse.AuthenticatorAttachment is not null)
        {
            if (!AuthenticatorAttachmentSerializer.TryDeserialize(registrationResponse.AuthenticatorAttachment, out var attachment))
            {
                return Result<RegistrationResponse>.Fail();
            }

            authenticatorAttachment = attachment.Value;
        }

        if (!PublicKeyCredentialTypeSerializer.TryDeserialize(registrationResponse.Type, out var type))
        {
            return Result<RegistrationResponse>.Fail();
        }

        var result = new RegistrationResponse(
            id,
            rawId,
            responseResult.Ok,
            authenticatorAttachment,
            registrationResponse.ClientExtensionResults,
            type.Value);
        return Result<RegistrationResponse>.Success(result);
    }

    protected virtual Result<AuthenticatorAttestationResponse> DecodeAttestationResponse(
        AuthenticatorAttestationResponseJSON attestationResponseJson)
    {
        ArgumentNullException.ThrowIfNull(attestationResponseJson);
        if (!Base64Url.TryDecode(attestationResponseJson.ClientDataJson, out var clientDataJson))
        {
            return Result<AuthenticatorAttestationResponse>.Fail();
        }

        byte[]? authenticatorData = null;
        if (attestationResponseJson.AuthenticatorData is not null && !Base64Url.TryDecode(attestationResponseJson.AuthenticatorData, out authenticatorData))
        {
            return Result<AuthenticatorAttestationResponse>.Fail();
        }

        AuthenticatorTransport[]? transports = null;
        if (attestationResponseJson.Transports is not null)
        {
            transports = new AuthenticatorTransport[attestationResponseJson.Transports.Length];
            for (var i = 0; i < attestationResponseJson.Transports.Length; i++)
            {
                if (!AuthenticatorTransportSerializer.TryDeserialize(attestationResponseJson.Transports[i], out var transport))
                {
                    return Result<AuthenticatorAttestationResponse>.Fail();
                }

                transports[i] = transport.Value;
            }
        }

        byte[]? publicKey = null;
        if (attestationResponseJson.PublicKey is not null && !Base64Url.TryDecode(attestationResponseJson.PublicKey, out publicKey))
        {
            return Result<AuthenticatorAttestationResponse>.Fail();
        }

        CoseAlgorithm? publicKeyAlgorithm = null;
        if (attestationResponseJson.PublicKeyAlgorithm.HasValue)
        {
            var castedAlgorithm = (CoseAlgorithm) attestationResponseJson.PublicKeyAlgorithm.Value;
            if (!Enum.IsDefined(castedAlgorithm))
            {
                return Result<AuthenticatorAttestationResponse>.Fail();
            }

            publicKeyAlgorithm = castedAlgorithm;
        }

        if (!Base64Url.TryDecode(attestationResponseJson.AttestationObject, out var attestationObject))
        {
            return Result<AuthenticatorAttestationResponse>.Fail();
        }

        var result = new AuthenticatorAttestationResponse(
            clientDataJson,
            authenticatorData,
            transports,
            publicKey,
            publicKeyAlgorithm,
            attestationObject);
        return Result<AuthenticatorAttestationResponse>.Success(result);
    }
}
