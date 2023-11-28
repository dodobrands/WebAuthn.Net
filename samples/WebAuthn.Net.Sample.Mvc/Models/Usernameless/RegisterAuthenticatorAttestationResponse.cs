using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Sample.Mvc.Models.Usernameless;

public class RegisterAuthenticatorAttestationResponse
{
    [JsonConstructor]
    public RegisterAuthenticatorAttestationResponse(string clientDataJson, string attestationObject)
    {
        ClientDataJson = clientDataJson;
        AttestationObject = attestationObject;
    }

    [JsonPropertyName("clientDataJSON")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string ClientDataJson { get; }

    [JsonPropertyName("attestationObject")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string AttestationObject { get; }
}
