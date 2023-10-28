using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.CreateOptions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.Json;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.CreateOptions;
using WebAuthn.Net.Services.Serialization.Json;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Services.PublicKeyCredentialRequestOptionsEncoder.Implementation;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
[SuppressMessage("ReSharper", "StaticMemberInGenericType")]
public class DefaultPublicKeyCredentialRequestOptionsEncoder<TContext>
    : IPublicKeyCredentialRequestOptionsEncoder<TContext> where TContext : class, IWebAuthnContext
{
    protected static readonly EnumMemberAttributeMapper<PublicKeyCredentialType> PublicKeyCredentialTypeMapper = new();
    protected static readonly EnumMemberAttributeMapper<AuthenticatorTransport> AuthenticatorTransportMapper = new();
    protected static readonly EnumMemberAttributeMapper<UserVerificationRequirement> UserVerificationRequirementMapper = new();
    protected static readonly EnumMemberAttributeMapper<PublicKeyCredentialHints> PublicKeyCredentialHintsMapper = new();
    protected static readonly EnumMemberAttributeMapper<AttestationConveyancePreference> AttestationConveyancePreferenceMapper = new();
    protected static readonly EnumMemberAttributeMapper<AttestationStatementFormat> AttestationStatementFormatMapper = new();

    public Task<PublicKeyCredentialRequestOptionsJSON> EncodeAsync(
        TContext context,
        PublicKeyCredentialRequestOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        cancellationToken.ThrowIfCancellationRequested();
        var challenge = WebEncoders.Base64UrlEncode(options.Challenge);
        var allowCredentials = EncodeAllowCredentials(options.AllowCredentials);
        var userVerification = EncodeUserVerification(options.UserVerification);
        var hints = EncodeHints(options.Hints);
        var attestation = EncodeAttestation(options.Attestation);
        var attestationFormats = EncodeAttestationFormats(options.AttestationFormats);
        var extensions = EncodeExtensions(options.Extensions);
        var result = new PublicKeyCredentialRequestOptionsJSON(
            challenge,
            options.Timeout,
            options.RpId,
            allowCredentials,
            userVerification,
            hints,
            attestation,
            attestationFormats,
            extensions);
        return Task.FromResult(result);
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

    protected virtual string? EncodeUserVerification(UserVerificationRequirement? userVerification)
    {
        if (!userVerification.HasValue)
        {
            return null;
        }

        if (!UserVerificationRequirementMapper.TryGetStringFromEnum(userVerification.Value, out var encodedUserVerification))
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

    protected virtual AuthenticationExtensionsClientInputsJSON? EncodeExtensions(AuthenticationExtensionsClientInputs? extensions)
    {
        if (extensions is null)
        {
            return null;
        }

        return new();
    }
}
