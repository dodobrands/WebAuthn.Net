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

/// <summary>
///     Default implementation of <see cref="IPublicKeyCredentialRequestOptionsEncoder" />.
/// </summary>
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
[SuppressMessage("ReSharper", "StaticMemberInGenericType")]
public class DefaultPublicKeyCredentialRequestOptionsEncoder : IPublicKeyCredentialRequestOptionsEncoder
{
    /// <summary>
    ///     Constructs <see cref="DefaultPublicKeyCredentialRequestOptionsEncoder" />.
    /// </summary>
    /// <param name="publicKeyCredentialTypeSerializer">Serializer for the <see cref="PublicKeyCredentialType" /> enum.</param>
    /// <param name="authenticatorTransportSerializer">Serializer for the <see cref="AuthenticatorTransport" /> enum.</param>
    /// <param name="userVerificationRequirementSerializer">Serializer for the <see cref="UserVerificationRequirement" /> enum.</param>
    /// <param name="publicKeyCredentialHintsSerializer">Serializer for the <see cref="PublicKeyCredentialHints" /> enum.</param>
    /// <param name="attestationConveyancePreferenceSerializer">Serializer for the <see cref="AttestationConveyancePreference" /> enum.</param>
    /// <param name="attestationStatementFormatSerializer">Serializer for the <see cref="AttestationStatementFormat" /> enum.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
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

    /// <summary>
    ///     Serializer for the <see cref="PublicKeyCredentialType" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<PublicKeyCredentialType> PublicKeyCredentialTypeSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="AuthenticatorTransport" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<AuthenticatorTransport> AuthenticatorTransportSerializer { get; }

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
    public virtual PublicKeyCredentialRequestOptionsJSON Encode(PublicKeyCredentialRequestOptions options)
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

    /// <summary>
    ///     Encodes an array of <see cref="PublicKeyCredentialDescriptor" /> into an array of models suitable for serialization into JSON.
    /// </summary>
    /// <param name="allowCredentials">Array of <see cref="PublicKeyCredentialDescriptor" />, which needs to be encoded into models suitable for serialization into JSON.</param>
    /// <returns>Array of <see cref="PublicKeyCredentialDescriptorJSON" /> or <see langword="null" />.</returns>
    protected virtual PublicKeyCredentialDescriptorJSON[]? EncodeAllowCredentials(PublicKeyCredentialDescriptor[]? allowCredentials)
    {
        if (allowCredentials is null)
        {
            return null;
        }

        var result = new PublicKeyCredentialDescriptorJSON[allowCredentials.Length];
        for (var i = 0; i < allowCredentials.Length; i++)
        {
            result[i] = EncodeAllowCredential(allowCredentials[i]);
        }

        return result;
    }

    /// <summary>
    ///     Encodes <see cref="PublicKeyCredentialDescriptor" /> into a model suitable for serialization into JSON.
    /// </summary>
    /// <param name="allowCredential"><see cref="PublicKeyCredentialDescriptor" />, which needs to be encoded into a model suitable for serialization into JSON.</param>
    /// <returns><see cref="PublicKeyCredentialDescriptorJSON" />, suitable for serialization into JSON</returns>
    /// <exception cref="InvalidOperationException">Failed to encode <paramref name="allowCredential" />.<see cref="PublicKeyCredentialDescriptor.Type" /> or one of the <paramref name="allowCredential" />.<see cref="PublicKeyCredentialDescriptor.Transports" /> elements.</exception>
    protected virtual PublicKeyCredentialDescriptorJSON EncodeAllowCredential(PublicKeyCredentialDescriptor allowCredential)
    {
        ArgumentNullException.ThrowIfNull(allowCredential);
        var id = Base64Url.Encode(allowCredential.Id);
        if (!PublicKeyCredentialTypeSerializer.TrySerialize(allowCredential.Type, out var type))
        {
            throw new InvalidOperationException("Failed to encode type in PublicKeyCredentialDescriptor");
        }

        string[]? transports = null;
        if (allowCredential.Transports is not null)
        {
            transports = new string[allowCredential.Transports.Length];
            for (var i = 0; i < allowCredential.Transports.Length; i++)
            {
                var transportToEncode = allowCredential.Transports[i];
                if (!AuthenticatorTransportSerializer.TrySerialize(transportToEncode, out var encodedTransport))
                {
                    throw new InvalidOperationException("Failed to encode transports in PublicKeyCredentialDescriptor");
                }

                transports[i] = encodedTransport;
            }
        }

        return new(id, type, transports);
    }

    /// <summary>
    ///     Encodes the <see cref="UserVerificationRequirement" /> enum into a string.
    /// </summary>
    /// <param name="userVerification">The value of the <see cref="UserVerificationRequirement" /> enum that needs to be encoded into a string.</param>
    /// <returns>String representation of <see cref="UserVerificationRequirement" /> or <see langword="null" />.</returns>
    /// <exception cref="InvalidOperationException">Failed to encode <paramref name="userVerification" /> into a string.</exception>
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

    /// <summary>
    ///     Encodes an array of <see cref="PublicKeyCredentialHints" /> enums into an array of strings.
    /// </summary>
    /// <param name="hints">Array of <see cref="PublicKeyCredentialHints" />, which needs to be encoded into strings.</param>
    /// <returns>Array of strings or <see langword="null" />.</returns>
    /// <exception cref="InvalidOperationException">Failed to encode one of the elements in the <paramref name="hints" /> array.</exception>
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

    /// <summary>
    ///     Encodes the <see cref="AttestationConveyancePreference" /> enum into a string.
    /// </summary>
    /// <param name="attestation">The value of the <see cref="AttestationConveyancePreference" /> enum that needs to be encoded into a string.</param>
    /// <returns>String representation of <see cref="AttestationConveyancePreference" /> or <see langword="null" />.</returns>
    /// <exception cref="InvalidOperationException">Failed to encode <paramref name="attestation" /> into a string.</exception>
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

    /// <summary>
    ///     Encodes an array of <see cref="AttestationStatementFormat" /> enums into an array of strings.
    /// </summary>
    /// <param name="attestationFormats">Array of <see cref="AttestationStatementFormat" />, which needs to be encoded into strings.</param>
    /// <returns>Array of strings or <see langword="null" />.</returns>
    /// <exception cref="InvalidOperationException">Failed to encode one of the elements in the <paramref name="attestationFormats" /> array.</exception>
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
