using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateCredential;

namespace WebAuthn.Net.FidoConformance.Models.Attestation.CompleteCeremony.Request;

public class ServerPublicKeyCredential
{
    [JsonConstructor]
    public ServerPublicKeyCredential(string id, string type, ServerAuthenticatorAttestationResponse response)
    {
        Id = id;
        Type = type;
        Response = response;
    }

    [JsonPropertyName("id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string Id { get; }

    [JsonPropertyName("type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string Type { get; }

    [JsonPropertyName("response")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public ServerAuthenticatorAttestationResponse Response { get; }

    public CompleteRegistrationCeremonyRequest ToCompleteCeremonyRequest(string registrationCeremonyId)
    {
        var result = ToRegistrationResponseJson();
        return new(registrationCeremonyId, result);
    }

    private RegistrationResponseJSON ToRegistrationResponseJson()
    {
        var response = ParseResponse(Response);
        return new(
            Id,
            Id,
            response,
            null,
            null,
            Type);
    }

    private static AuthenticatorAttestationResponseJSON ParseResponse(ServerAuthenticatorAttestationResponse input)
    {
        return new(
            input.ClientDataJson,
            null,
            null,
            null,
            null,
            input.AttestationObject);
    }
}
