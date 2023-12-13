using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.Json;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateOptions;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.PublicKeyCredentialCreationOptionsEncoder.Implementation;

/// <summary>
///     Default implementation of <see cref="IPublicKeyCredentialCreationOptionsEncoder" />.
/// </summary>
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
[SuppressMessage("ReSharper", "StaticMemberInGenericType")]
public class DefaultPublicKeyCredentialCreationOptionsEncoder
    : IPublicKeyCredentialCreationOptionsEncoder
{
    /// <summary>
    ///     Constructs <see cref="DefaultPublicKeyCredentialCreationOptionsEncoder" />.
    /// </summary>
    /// <param name="publicKeyCredentialTypeSerializer">Serializer for the <see cref="PublicKeyCredentialType" /> enum.</param>
    /// <param name="authenticatorTransportSerializer">Serializer for the <see cref="AuthenticatorTransport" /> enum.</param>
    /// <param name="authenticatorAttachmentSerializer">Serializer for the <see cref="AuthenticatorAttachment" /> enum.</param>
    /// <param name="residentKeyRequirementSerializer">Serializer for the <see cref="ResidentKeyRequirement" /> enum.</param>
    /// <param name="userVerificationRequirementSerializer">Serializer for the <see cref="UserVerificationRequirement" /> enum.</param>
    /// <param name="publicKeyCredentialHintsSerializer">Serializer for the <see cref="PublicKeyCredentialHints" /> enum.</param>
    /// <param name="attestationConveyancePreferenceSerializer">Serializer for the <see cref="AttestationConveyancePreference" /> enum.</param>
    /// <param name="attestationStatementFormatSerializer">Serializer for the <see cref="AttestationStatementFormat" /> enum.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultPublicKeyCredentialCreationOptionsEncoder(
        IEnumMemberAttributeSerializer<PublicKeyCredentialType> publicKeyCredentialTypeSerializer,
        IEnumMemberAttributeSerializer<AuthenticatorTransport> authenticatorTransportSerializer,
        IEnumMemberAttributeSerializer<AuthenticatorAttachment> authenticatorAttachmentSerializer,
        IEnumMemberAttributeSerializer<ResidentKeyRequirement> residentKeyRequirementSerializer,
        IEnumMemberAttributeSerializer<UserVerificationRequirement> userVerificationRequirementSerializer,
        IEnumMemberAttributeSerializer<PublicKeyCredentialHints> publicKeyCredentialHintsSerializer,
        IEnumMemberAttributeSerializer<AttestationConveyancePreference> attestationConveyancePreferenceSerializer,
        IEnumMemberAttributeSerializer<AttestationStatementFormat> attestationStatementFormatSerializer)
    {
        ArgumentNullException.ThrowIfNull(publicKeyCredentialTypeSerializer);
        ArgumentNullException.ThrowIfNull(authenticatorTransportSerializer);
        ArgumentNullException.ThrowIfNull(authenticatorAttachmentSerializer);
        ArgumentNullException.ThrowIfNull(residentKeyRequirementSerializer);
        ArgumentNullException.ThrowIfNull(userVerificationRequirementSerializer);
        ArgumentNullException.ThrowIfNull(publicKeyCredentialHintsSerializer);
        ArgumentNullException.ThrowIfNull(attestationConveyancePreferenceSerializer);
        ArgumentNullException.ThrowIfNull(attestationStatementFormatSerializer);
        PublicKeyCredentialTypeSerializer = publicKeyCredentialTypeSerializer;
        AuthenticatorTransportSerializer = authenticatorTransportSerializer;
        AuthenticatorAttachmentSerializer = authenticatorAttachmentSerializer;
        ResidentKeyRequirementSerializer = residentKeyRequirementSerializer;
        UserVerificationRequirementSerializer = userVerificationRequirementSerializer;
        PublicKeyCredentialHintsSerializer = publicKeyCredentialHintsSerializer;
        AttestationConveyancePreferenceSerializer = attestationConveyancePreferenceSerializer;
        AttestationStatementFormatSerializer = attestationStatementFormatSerializer;
    }

    /// <summary>
    ///     Serializer for the <see cref="PublicKeyCredentialType" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<PublicKeyCredentialType> PublicKeyCredentialTypeSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="AuthenticatorTransport" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<AuthenticatorTransport> AuthenticatorTransportSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="AuthenticatorAttachment" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<AuthenticatorAttachment> AuthenticatorAttachmentSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="ResidentKeyRequirement" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<ResidentKeyRequirement> ResidentKeyRequirementSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="UserVerificationRequirement" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<UserVerificationRequirement> UserVerificationRequirementSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="PublicKeyCredentialHints" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<PublicKeyCredentialHints> PublicKeyCredentialHintsSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="AttestationConveyancePreference" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<AttestationConveyancePreference> AttestationConveyancePreferenceSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="AttestationStatementFormat" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<AttestationStatementFormat> AttestationStatementFormatSerializer { get; }

    /// <inheritdoc />
    public virtual PublicKeyCredentialCreationOptionsJSON Encode(PublicKeyCredentialCreationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var rp = EncodeRp(options.Rp);
        var user = EncodeUser(options.User);
        var challenge = Base64Url.Encode(options.Challenge);
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

    private static PublicKeyCredentialRpEntityJSON EncodeRp(PublicKeyCredentialRpEntity rp)
    {
        ArgumentNullException.ThrowIfNull(rp);
        return new(rp.Name, rp.Id);
    }

    private static PublicKeyCredentialUserEntityJSON EncodeUser(PublicKeyCredentialUserEntity user)
    {
        ArgumentNullException.ThrowIfNull(user);
        var id = Base64Url.Encode(user.Id);
        return new(id, user.Name, user.DisplayName);
    }

    private PublicKeyCredentialParametersJSON[] EncodePubKeyCredParams(PublicKeyCredentialParameters[] pubKeyCredParams)
    {
        ArgumentNullException.ThrowIfNull(pubKeyCredParams);
        var result = new PublicKeyCredentialParametersJSON[pubKeyCredParams.Length];
        for (var i = 0; i < pubKeyCredParams.Length; i++)
        {
            result[i] = EncodePubKeyCredParam(pubKeyCredParams[i]);
        }

        return result;
    }

    private PublicKeyCredentialParametersJSON EncodePubKeyCredParam(PublicKeyCredentialParameters pubKeyCredParam)
    {
        ArgumentNullException.ThrowIfNull(pubKeyCredParam);
        if (!PublicKeyCredentialTypeSerializer.TrySerialize(pubKeyCredParam.Type, out var type))
        {
            throw new InvalidOperationException("Failed to encode type in PublicKeyCredentialParameters");
        }

        var alg = (long) pubKeyCredParam.Alg;
        return new(type, alg);
    }

    private PublicKeyCredentialDescriptorJSON[]? EncodeExcludeCredentials(PublicKeyCredentialDescriptor[]? excludeCredentials)
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

    private PublicKeyCredentialDescriptorJSON EncodeExcludeCredential(PublicKeyCredentialDescriptor excludeCredential)
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

    private AuthenticatorSelectionCriteriaJSON? EncodeAuthenticatorSelection(AuthenticatorSelectionCriteria? authenticatorSelection)
    {
        if (authenticatorSelection is null)
        {
            return null;
        }

        string? authenticatorAttachment = null;
        if (authenticatorSelection.AuthenticatorAttachment.HasValue)
        {
            if (!AuthenticatorAttachmentSerializer.TrySerialize(authenticatorSelection.AuthenticatorAttachment.Value, out var resultAuthenticatorAttachment))
            {
                throw new InvalidOperationException("Failed to encode authenticatorAttachment in AuthenticatorSelectionCriteria");
            }

            authenticatorAttachment = resultAuthenticatorAttachment;
        }

        string? residentKey = null;
        if (authenticatorSelection.ResidentKey.HasValue)
        {
            if (!ResidentKeyRequirementSerializer.TrySerialize(authenticatorSelection.ResidentKey.Value, out var resultResidentKey))
            {
                throw new InvalidOperationException("Failed to encode residentKey in AuthenticatorSelectionCriteria");
            }

            residentKey = resultResidentKey;
        }

        string? userVerification = null;
        if (authenticatorSelection.UserVerification.HasValue)
        {
            if (!UserVerificationRequirementSerializer.TrySerialize(authenticatorSelection.UserVerification.Value, out var resultUserVerification))
            {
                throw new InvalidOperationException("Failed to encode userVerification in AuthenticatorSelectionCriteria");
            }

            userVerification = resultUserVerification;
        }

        return new(authenticatorAttachment, residentKey, authenticatorSelection.RequireResidentKey, userVerification);
    }

    private string[]? EncodeHints(PublicKeyCredentialHints[]? hints)
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

    private string? EncodeAttestation(AttestationConveyancePreference? attestation)
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

    private string[]? EncodeAttestationFormats(AttestationStatementFormat[]? attestationFormats)
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
