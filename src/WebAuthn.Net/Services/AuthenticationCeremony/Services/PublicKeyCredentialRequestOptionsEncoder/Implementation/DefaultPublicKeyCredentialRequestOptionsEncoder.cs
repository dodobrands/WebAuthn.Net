using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.CreateOptions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.Json;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.CreateOptions;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Services.PublicKeyCredentialRequestOptionsEncoder.Implementation;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
[SuppressMessage("ReSharper", "StaticMemberInGenericType")]
public class DefaultPublicKeyCredentialRequestOptionsEncoder : IPublicKeyCredentialRequestOptionsEncoder
{
    public DefaultPublicKeyCredentialRequestOptionsEncoder(
        IEnumMemberAttributeSerializer<PublicKeyCredentialType> publicKeyCredentialTypeSerializer,
        IEnumMemberAttributeSerializer<AuthenticatorTransport> authenticatorTransportSerializer,
        IEnumMemberAttributeSerializer<UserVerificationRequirement> userVerificationRequirementSerializer,
        IEnumMemberAttributeSerializer<PublicKeyCredentialHints> publicKeyCredentialHintsSerializer,
        IEnumMemberAttributeSerializer<AttestationConveyancePreference> attestationConveyancePreferenceSerializer,
        IEnumMemberAttributeSerializer<AttestationStatementFormat> attestationStatementFormatSerializer)
    {
        ArgumentNullException.ThrowIfNull(publicKeyCredentialTypeSerializer);
        ArgumentNullException.ThrowIfNull(authenticatorTransportSerializer);
        ArgumentNullException.ThrowIfNull(userVerificationRequirementSerializer);
        ArgumentNullException.ThrowIfNull(publicKeyCredentialHintsSerializer);
        ArgumentNullException.ThrowIfNull(attestationConveyancePreferenceSerializer);
        ArgumentNullException.ThrowIfNull(attestationStatementFormatSerializer);
        PublicKeyCredentialTypeSerializer = publicKeyCredentialTypeSerializer;
        AuthenticatorTransportSerializer = authenticatorTransportSerializer;
        UserVerificationRequirementSerializer = userVerificationRequirementSerializer;
        PublicKeyCredentialHintsSerializer = publicKeyCredentialHintsSerializer;
        AttestationConveyancePreferenceSerializer = attestationConveyancePreferenceSerializer;
        AttestationStatementFormatSerializer = attestationStatementFormatSerializer;
    }

    protected IEnumMemberAttributeSerializer<PublicKeyCredentialType> PublicKeyCredentialTypeSerializer { get; }
    protected IEnumMemberAttributeSerializer<AuthenticatorTransport> AuthenticatorTransportSerializer { get; }
    protected IEnumMemberAttributeSerializer<UserVerificationRequirement> UserVerificationRequirementSerializer { get; }
    protected IEnumMemberAttributeSerializer<PublicKeyCredentialHints> PublicKeyCredentialHintsSerializer { get; }
    protected IEnumMemberAttributeSerializer<AttestationConveyancePreference> AttestationConveyancePreferenceSerializer { get; }
    protected IEnumMemberAttributeSerializer<AttestationStatementFormat> AttestationStatementFormatSerializer { get; }

    public PublicKeyCredentialRequestOptionsJSON Encode(PublicKeyCredentialRequestOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var challenge = Base64Url.Encode(options.Challenge);
        var allowCredentials = EncodeAllowCredentials(options.AllowCredentials);
        var userVerification = EncodeUserVerification(options.UserVerification);
        var hints = EncodeHints(options.Hints);
        var attestation = EncodeAttestation(options.Attestation);
        var attestationFormats = EncodeAttestationFormats(options.AttestationFormats);
        var result = new PublicKeyCredentialRequestOptionsJSON(
            challenge,
            options.Timeout,
            options.RpId,
            allowCredentials,
            userVerification,
            hints,
            attestation,
            attestationFormats,
            options.Extensions);
        return result;
    }

    protected virtual PublicKeyCredentialDescriptorJSON[]? EncodeAllowCredentials(PublicKeyCredentialDescriptor[]? excludeCredentials)
    {
        if (excludeCredentials is null)
        {
            return null;
        }

        var result = new PublicKeyCredentialDescriptorJSON[excludeCredentials.Length];
        for (var i = 0; i < excludeCredentials.Length; i++)
        {
            result[i] = EncodeAllowCredential(excludeCredentials[i]);
        }

        return result;
    }

    protected virtual PublicKeyCredentialDescriptorJSON EncodeAllowCredential(PublicKeyCredentialDescriptor excludeCredential)
    {
        ArgumentNullException.ThrowIfNull(excludeCredential);
        var id = Base64Url.Encode(excludeCredential.Id);
        if (!PublicKeyCredentialTypeSerializer.TrySerialize(excludeCredential.Type, out var type))
        {
            throw new InvalidOperationException("Failed to encode type in PublicKeyCredentialDescriptor");
        }

        string[]? transports = null;
        if (excludeCredential.Transports is not null)
        {
            transports = new string[excludeCredential.Transports.Length];
            for (var i = 0; i < excludeCredential.Transports.Length; i++)
            {
                var transportToEncode = excludeCredential.Transports[i];
                if (!AuthenticatorTransportSerializer.TrySerialize(transportToEncode, out var encodedTransport))
                {
                    throw new InvalidOperationException("Failed to encode transports in PublicKeyCredentialDescriptor");
                }

                transports[i] = encodedTransport;
            }
        }

        return new(id, type, transports);
    }

    protected virtual string? EncodeUserVerification(UserVerificationRequirement? userVerification)
    {
        if (!userVerification.HasValue)
        {
            return null;
        }

        if (!UserVerificationRequirementSerializer.TrySerialize(userVerification.Value, out var encodedUserVerification))
        {
            throw new InvalidOperationException("Failed to encode userVerification");
        }

        return encodedUserVerification;
    }

    protected virtual string[]? EncodeHints(PublicKeyCredentialHints[]? hints)
    {
        if (hints is null)
        {
            return null;
        }

        var result = new string[hints.Length];
        for (var i = 0; i < hints.Length; i++)
        {
            if (!PublicKeyCredentialHintsSerializer.TrySerialize(hints[i], out var resultHint))
            {
                throw new InvalidOperationException("Failed to encode hint in hints");
            }

            result[i] = resultHint;
        }

        return result;
    }

    protected virtual string? EncodeAttestation(AttestationConveyancePreference? attestation)
    {
        if (!attestation.HasValue)
        {
            return null;
        }

        if (!AttestationConveyancePreferenceSerializer.TrySerialize(attestation.Value, out var result))
        {
            throw new InvalidOperationException("Failed to encode attestation");
        }

        return result;
    }

    protected virtual string[]? EncodeAttestationFormats(AttestationStatementFormat[]? attestationFormats)
    {
        if (attestationFormats is null)
        {
            return null;
        }

        var result = new string[attestationFormats.Length];
        for (var i = 0; i < attestationFormats.Length; i++)
        {
            if (!AttestationStatementFormatSerializer.TrySerialize(attestationFormats[i], out var resultHint))
            {
                throw new InvalidOperationException("Failed to encode attestationFormats");
            }

            result[i] = resultHint;
        }

        return result;
    }
}
