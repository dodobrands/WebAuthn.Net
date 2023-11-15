using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.WebUtilities;
using WebAuthn.Net.FidoConformance.Constants;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.Serialization.Json;
using Host = WebAuthn.Net.FidoConformance.Constants.Host;

namespace WebAuthn.Net.FidoConformance.Models.Attestation.CreateOptions.Request;

public class ServerPublicKeyCredentialCreationOptionsRequest
{
    private static readonly EnumMemberAttributeMapper<AuthenticatorAttachment> AuthenticatorAttachmentMapper = new();
    private static readonly EnumMemberAttributeMapper<ResidentKeyRequirement> ResidentKeyRequirementMapper = new();
    private static readonly EnumMemberAttributeMapper<UserVerificationRequirement> UserVerificationRequirementMapper = new();
    private static readonly EnumMemberAttributeMapper<AttestationConveyancePreference> AttestationMapper = new();

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

    public BeginRegistrationCeremonyRequest ToBeginCeremonyRequest()
    {
        var authenticatorSelection = ParseAuthenticatorSelection(AuthenticatorSelection);
        var attestation = ParseNullableEnum(Attestation, AttestationMapper);

        return new(
            null,
            null,
            Host.WebAuthnDisplayName,
            new(UserName, WebEncoders.Base64UrlDecode(UserName), DisplayName),
            16,
            CoseAlgorithms.All,
            120000,
            RegistrationCeremonyExcludeCredentials.AllExisting(),
            authenticatorSelection,
            null,
            attestation,
            null,
            Extensions);
    }

    private static Net.Models.Protocol.RegistrationCeremony.CreateOptions.AuthenticatorSelectionCriteria? ParseAuthenticatorSelection(AuthenticatorSelectionCriteria? input)
    {
        if (input is null)
        {
            return null;
        }

        var authenticatorAttachment = ParseNullableEnum(input.AuthenticatorAttachment, AuthenticatorAttachmentMapper);
        var residentKey = ParseNullableEnum(input.ResidentKey, ResidentKeyRequirementMapper);
        var requireResidentKey = input.RequireResidentKey;
        var userVerification = ParseNullableEnum(input.UserVerification, UserVerificationRequirementMapper);
        return new(
            authenticatorAttachment,
            residentKey,
            requireResidentKey,
            userVerification);
    }

    private static TEnum? ParseNullableEnum<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields)] TEnum>(
        string? value,
        EnumMemberAttributeMapper<TEnum> mapper)
        where TEnum : struct, Enum
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        if (!mapper.TryGetEnumFromString(value, out var result))
        {
            throw new ArgumentOutOfRangeException(nameof(value), "The value is not in the set of acceptable ones");
        }

        return result.Value;
    }
}
