using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Demo.FidoConformance.Models.Assertion.CompleteCeremony.Request;

public class ServerAuthenticatorAssertionResponse
{
    [JsonConstructor]
    public ServerAuthenticatorAssertionResponse(
        string clientDataJson,
        string authenticatorData,
        string signature,
        string userHandle,
        string? attestationObject)
    {
        ClientDataJson = clientDataJson;
        AuthenticatorData = authenticatorData;
        Signature = signature;
        UserHandle = userHandle;
        AttestationObject = attestationObject;
    }

    [JsonPropertyName("clientDataJSON")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string ClientDataJson { get; }

    [JsonPropertyName("authenticatorData")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string AuthenticatorData { get; }

    [JsonPropertyName("signature")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Signature { get; }

    [JsonPropertyName("userHandle")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string UserHandle { get; }

    [JsonPropertyName("attestationObject")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? AttestationObject { get; }
}
