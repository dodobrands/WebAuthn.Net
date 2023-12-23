using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Demo.FidoConformance.Models.Attestation.CompleteCeremony.Request;

public class ServerAuthenticatorAttestationResponse
{
    [JsonConstructor]
    public ServerAuthenticatorAttestationResponse(string clientDataJson, string attestationObject)
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
