using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using WebAuthn.Net.Demo.FidoConformance.Constants;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Serialization.Json.Implementation;
using WebAuthn.Net.Services.Static;
using Host = WebAuthn.Net.Demo.FidoConformance.Constants.Host;

namespace WebAuthn.Net.Demo.FidoConformance.Models.Attestation.CreateOptions.Request;

public class ServerPublicKeyCredentialCreationOptionsRequest
{
    private static readonly IEnumMemberAttributeSerializer<AuthenticatorAttachment> AuthenticatorAttachmentSerializer
        = new DefaultEnumMemberAttributeSerializer<AuthenticatorAttachment>();

    private static readonly IEnumMemberAttributeSerializer<ResidentKeyRequirement> ResidentKeyRequirementSerializer
        = new DefaultEnumMemberAttributeSerializer<ResidentKeyRequirement>();

    private static readonly IEnumMemberAttributeSerializer<UserVerificationRequirement> UserVerificationRequirementSerializer
        = new DefaultEnumMemberAttributeSerializer<UserVerificationRequirement>();

    private static readonly IEnumMemberAttributeSerializer<AttestationConveyancePreference> AttestationConveyancePreferenceSerializer
        = new DefaultEnumMemberAttributeSerializer<AttestationConveyancePreference>();


    [JsonConstructor]
    public ServerPublicKeyCredentialCreationOptionsRequest(
        string userName,
        string displayName,
        AuthenticatorSelectionCriteria? authenticatorSelection,
        string? attestation,
        Dictionary<string, JsonElement>? extensions)
    {
        UserName = userName;
        DisplayName = displayName;
        AuthenticatorSelection = authenticatorSelection;
        Attestation = attestation;
        Extensions = extensions;
    }


    [JsonPropertyName("username")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string UserName { get; }

    [JsonPropertyName("displayName")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string DisplayName { get; }

    [JsonPropertyName("authenticatorSelection")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public AuthenticatorSelectionCriteria? AuthenticatorSelection { get; }

    [JsonPropertyName("attestation")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? Attestation { get; }

    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public Dictionary<string, JsonElement>? Extensions { get; }

    public bool TryToBeginCeremonyRequest([NotNullWhen(true)] out BeginRegistrationCeremonyRequest? result)
    {
        Net.Models.Protocol.RegistrationCeremony.CreateOptions.AuthenticatorSelectionCriteria? authenticatorSelection = null;
        if (AuthenticatorSelection is not null)
        {
            if (!TryParseAuthenticatorSelection(AuthenticatorSelection, out var parsedAuthenticatorSelection))
            {
                result = null;
                return false;
            }

            authenticatorSelection = parsedAuthenticatorSelection;
        }

        if (!TryParseNullableEnum(Attestation, AttestationConveyancePreferenceSerializer, out var attestation))
        {
            result = null;
            return false;
        }

        if (!Base64Url.TryDecode(UserName, out var userHandle))
        {
            result = null;
            return false;
        }

        result = new(
            null,
            null,
            Host.WebAuthnDisplayName,
            new(UserName, userHandle, DisplayName),
            16,
            CoseAlgorithms.All,
            120000,
            RegistrationCeremonyExcludeCredentials.AllExisting(),
            authenticatorSelection,
            null,
            attestation,
            null,
            Extensions);
        return true;
    }

    private static bool TryParseAuthenticatorSelection(
        AuthenticatorSelectionCriteria input,
        [NotNullWhen(true)] out Net.Models.Protocol.RegistrationCeremony.CreateOptions.AuthenticatorSelectionCriteria? result)
    {
        if (!TryParseNullableEnum(input.AuthenticatorAttachment, AuthenticatorAttachmentSerializer, out var authenticatorAttachment))
        {
            result = null;
            return false;
        }

        if (!TryParseNullableEnum(input.ResidentKey, ResidentKeyRequirementSerializer, out var residentKey))
        {
            result = null;
            return false;
        }

        if (!TryParseNullableEnum(input.UserVerification, UserVerificationRequirementSerializer, out var userVerification))
        {
            result = null;
            return false;
        }

        var requireResidentKey = input.RequireResidentKey;
        result = new(
            authenticatorAttachment,
            residentKey,
            requireResidentKey,
            userVerification);
        return true;
    }

    private static bool TryParseNullableEnum<TEnum>(
        string? value,
        IEnumMemberAttributeSerializer<TEnum> mapper,
        out TEnum? result)
        where TEnum : struct, Enum
    {
        if (string.IsNullOrEmpty(value))
        {
            result = null;
            return true;
        }

        if (!mapper.TryDeserialize(value, out var parsedResult))
        {
            result = null;
            return false;
        }

        result = parsedResult.Value;
        return true;
    }
}
