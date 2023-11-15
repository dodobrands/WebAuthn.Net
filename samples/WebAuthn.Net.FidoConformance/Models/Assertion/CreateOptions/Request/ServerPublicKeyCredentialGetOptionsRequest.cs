using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.Serialization.Json;

namespace WebAuthn.Net.FidoConformance.Models.Assertion.CreateOptions.Request;

public class ServerPublicKeyCredentialGetOptionsRequest
{
    private static readonly EnumMemberAttributeMapper<UserVerificationRequirement> UserVerificationRequirementMapper = new();

    [JsonConstructor]
    public ServerPublicKeyCredentialGetOptionsRequest(string userName, string? userVerification)
    {
        UserName = userName;
        UserVerification = userVerification;
    }

    [JsonPropertyName("username")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string UserName { get; }

    [JsonPropertyName("userVerification  ")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? UserVerification { get; }

    public BeginAuthenticationCeremonyRequest ToBeginCeremonyRequest()
    {
        var userVerification = ParseNullableEnum(UserVerification, UserVerificationRequirementMapper);
        return new(
            null,
            null,
            null,
            16,
            120000,
            null,
            userVerification,
            null,
            null,
            null,
            null);
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
