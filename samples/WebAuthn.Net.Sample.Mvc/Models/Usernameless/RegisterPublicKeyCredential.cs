using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.Json.Serialization;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateCredential;

namespace WebAuthn.Net.Sample.Mvc.Models.Usernameless;

public class RegisterPublicKeyCredential
{
    [JsonConstructor]
    public RegisterPublicKeyCredential(
        string id,
        string type,
        Register.ServerAuthenticatorAttestationResponse response,
        Dictionary<string, JsonElement>? getClientExtensionResults)
    {
        Id = id;
        Type = type;
        Response = response;
        GetClientExtensionResults = getClientExtensionResults;
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
    public Register.ServerAuthenticatorAttestationResponse Response { get; }

    [JsonPropertyName("getClientExtensionResults")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public Dictionary<string, JsonElement>? GetClientExtensionResults { get; }

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
            GetClientExtensionResults ?? new Dictionary<string, JsonElement>(),
            Type);
    }

    private static AuthenticatorAttestationResponseJSON ParseResponse(Register.ServerAuthenticatorAttestationResponse input)
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
