using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.WebUtilities;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.Json;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateOptions;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;
using WebAuthn.Net.Services.Serialization.Json;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.PublicKeyCredentialCreationOptionsEncoder.Implementation;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
[SuppressMessage("ReSharper", "StaticMemberInGenericType")]
public class DefaultPublicKeyCredentialCreationOptionsEncoder
    : IPublicKeyCredentialCreationOptionsEncoder
{
    protected static readonly EnumMemberAttributeMapper<PublicKeyCredentialType> PublicKeyCredentialTypeMapper = new();
    protected static readonly EnumMemberAttributeMapper<AuthenticatorTransport> AuthenticatorTransportMapper = new();
    protected static readonly EnumMemberAttributeMapper<AuthenticatorAttachment> AuthenticatorAttachmentMapper = new();
    protected static readonly EnumMemberAttributeMapper<ResidentKeyRequirement> ResidentKeyRequirementMapper = new();
    protected static readonly EnumMemberAttributeMapper<UserVerificationRequirement> UserVerificationRequirementMapper = new();
    protected static readonly EnumMemberAttributeMapper<PublicKeyCredentialHints> PublicKeyCredentialHintsMapper = new();
    protected static readonly EnumMemberAttributeMapper<AttestationConveyancePreference> AttestationConveyancePreferenceMapper = new();
    protected static readonly EnumMemberAttributeMapper<AttestationStatementFormat> AttestationStatementFormatMapper = new();

    public PublicKeyCredentialCreationOptionsJSON Encode(PublicKeyCredentialCreationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var rp = EncodeRp(options.Rp);
        var user = EncodeUser(options.User);
        var challenge = WebEncoders.Base64UrlEncode(options.Challenge);
        var pubKeyCredParams = EncodePubKeyCredParams(options.PubKeyCredParams);
        var excludeCredentials = EncodeExcludeCredentials(options.ExcludeCredentials);
        var authenticatorSelection = EncodeAuthenticatorSelection(options.AuthenticatorSelection);
        var hints = EncodeHints(options.Hints);
        var attestation = EncodeAttestation(options.Attestation);
        var attestationFormats = EncodeAttestationFormats(options.AttestationFormats);
        var result = new PublicKeyCredentialCreationOptionsJSON(
            rp,
            user,
            challenge,
            pubKeyCredParams,
            options.Timeout,
            excludeCredentials,
            authenticatorSelection,
            hints,
            attestation,
            attestationFormats,
            options.Extensions);
        return result;
    }

    protected virtual PublicKeyCredentialRpEntityJSON EncodeRp(PublicKeyCredentialRpEntity rp)
    {
        ArgumentNullException.ThrowIfNull(rp);
        return new(rp.Name, rp.Id);
    }

    protected virtual PublicKeyCredentialUserEntityJSON EncodeUser(PublicKeyCredentialUserEntity user)
    {
        ArgumentNullException.ThrowIfNull(user);
        var id = WebEncoders.Base64UrlEncode(user.Id);
        return new(id, user.Name, user.DisplayName);
    }

    protected virtual PublicKeyCredentialParametersJSON[] EncodePubKeyCredParams(PublicKeyCredentialParameters[] pubKeyCredParams)
    {
        ArgumentNullException.ThrowIfNull(pubKeyCredParams);
        var result = new PublicKeyCredentialParametersJSON[pubKeyCredParams.Length];
        for (var i = 0; i < pubKeyCredParams.Length; i++)
        {
            result[i] = EncodePubKeyCredParam(pubKeyCredParams[i]);
        }

        return result;
    }

    protected virtual PublicKeyCredentialParametersJSON EncodePubKeyCredParam(PublicKeyCredentialParameters pubKeyCredParam)
    {
        ArgumentNullException.ThrowIfNull(pubKeyCredParam);
        if (!PublicKeyCredentialTypeMapper.TryGetStringFromEnum(pubKeyCredParam.Type, out var type))
        {
            throw new InvalidOperationException("Failed to encode type in PublicKeyCredentialParameters");
        }

        var alg = (long) pubKeyCredParam.Alg;
        return new(type, alg);
    }

    protected virtual PublicKeyCredentialDescriptorJSON[]? EncodeExcludeCredentials(PublicKeyCredentialDescriptor[]? excludeCredentials)
    {
        if (excludeCredentials is null)
        {
            return null;
        }

        var result = new PublicKeyCredentialDescriptorJSON[excludeCredentials.Length];
        for (var i = 0; i < excludeCredentials.Length; i++)
        {
            result[i] = EncodeExcludeCredential(excludeCredentials[i]);
        }

        return result;
    }

    protected virtual PublicKeyCredentialDescriptorJSON EncodeExcludeCredential(PublicKeyCredentialDescriptor excludeCredential)
    {
        ArgumentNullException.ThrowIfNull(excludeCredential);
        var id = WebEncoders.Base64UrlEncode(excludeCredential.Id);
        if (!PublicKeyCredentialTypeMapper.TryGetStringFromEnum(excludeCredential.Type, out var type))
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
                if (!AuthenticatorTransportMapper.TryGetStringFromEnum(transportToEncode, out var encodedTransport))
                {
                    throw new InvalidOperationException("Failed to encode transports in PublicKeyCredentialDescriptor");
                }

                transports[i] = encodedTransport;
            }
        }

        return new(id, type, transports);
    }

    protected virtual AuthenticatorSelectionCriteriaJSON? EncodeAuthenticatorSelection(AuthenticatorSelectionCriteria? authenticatorSelection)
    {
        if (authenticatorSelection is null)
        {
            return null;
        }

        string? authenticatorAttachment = null;
        if (authenticatorSelection.AuthenticatorAttachment.HasValue)
        {
            if (!AuthenticatorAttachmentMapper.TryGetStringFromEnum(authenticatorSelection.AuthenticatorAttachment.Value, out var resultAuthenticatorAttachment))
            {
                throw new InvalidOperationException("Failed to encode authenticatorAttachment in AuthenticatorSelectionCriteria");
            }

            authenticatorAttachment = resultAuthenticatorAttachment;
        }

        string? residentKey = null;
        if (authenticatorSelection.ResidentKey.HasValue)
        {
            if (!ResidentKeyRequirementMapper.TryGetStringFromEnum(authenticatorSelection.ResidentKey.Value, out var resultResidentKey))
            {
                throw new InvalidOperationException("Failed to encode residentKey in AuthenticatorSelectionCriteria");
            }

            residentKey = resultResidentKey;
        }

        string? userVerification = null;
        if (authenticatorSelection.UserVerification.HasValue)
        {
            if (!UserVerificationRequirementMapper.TryGetStringFromEnum(authenticatorSelection.UserVerification.Value, out var resultUserVerification))
            {
                throw new InvalidOperationException("Failed to encode userVerification in AuthenticatorSelectionCriteria");
            }

            userVerification = resultUserVerification;
        }

        return new(authenticatorAttachment, residentKey, authenticatorSelection.RequireResidentKey, userVerification);
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
            if (!PublicKeyCredentialHintsMapper.TryGetStringFromEnum(hints[i], out var resultHint))
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

        if (!AttestationConveyancePreferenceMapper.TryGetStringFromEnum(attestation.Value, out var result))
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
            if (!AttestationStatementFormatMapper.TryGetStringFromEnum(attestationFormats[i], out var resultHint))
            {
                throw new InvalidOperationException("Failed to encode attestationFormats");
            }

            result[i] = resultHint;
        }

        return result;
    }
}
