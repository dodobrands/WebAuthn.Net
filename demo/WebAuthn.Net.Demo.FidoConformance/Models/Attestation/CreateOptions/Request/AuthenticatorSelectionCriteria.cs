using System.Text.Json.Serialization;

namespace WebAuthn.Net.Demo.FidoConformance.Models.Attestation.CreateOptions.Request;

public class AuthenticatorSelectionCriteria
{
    [JsonConstructor]
    public AuthenticatorSelectionCriteria(
        string? authenticatorAttachment,
        string? residentKey,
        bool? requireResidentKey,
        string? userVerification)
    {
        AuthenticatorAttachment = authenticatorAttachment;
        ResidentKey = residentKey;
        RequireResidentKey = requireResidentKey;
        UserVerification = userVerification;
    }

    [JsonPropertyName("authenticatorAttachment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? AuthenticatorAttachment { get; }

    [JsonPropertyName("residentKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? ResidentKey { get; }

    [JsonPropertyName("requireResidentKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool? RequireResidentKey { get; }

    [JsonPropertyName("userVerification")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? UserVerification { get; }
}
