using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Serialization.Json.Implementation;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Demo.FidoConformance.Models.Assertion.CreateOptions.Request;

public class ServerPublicKeyCredentialGetOptionsRequest
{
    private static readonly IEnumMemberAttributeSerializer<UserVerificationRequirement> UserVerificationRequirementSerializer
        = new DefaultEnumMemberAttributeSerializer<UserVerificationRequirement>();

    public ServerPublicKeyCredentialGetOptionsRequest(
        string userName,
        string? userVerification,
        Dictionary<string, JsonElement>? extensions)
    {
        UserName = userName;
        UserVerification = userVerification;
        Extensions = extensions;
    }

    [JsonPropertyName("username")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string UserName { get; }

    [JsonPropertyName("userVerification")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? UserVerification { get; }

    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public Dictionary<string, JsonElement>? Extensions { get; }

    public bool TryToBeginCeremonyRequest([NotNullWhen(true)] out BeginAuthenticationCeremonyRequest? result)
    {
        if (!TryParseNullableEnum(UserVerification, UserVerificationRequirementSerializer, out var userVerification))
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
            userHandle,
            16,
            120000,
            AuthenticationCeremonyIncludeCredentials.AllExisting(),
            userVerification,
            null,
            null,
            null,
            Extensions);
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
