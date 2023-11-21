using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using WebAuthn.Net.Storage.AuthenticationCeremony.Models;

namespace WebAuthn.Net.Storage.AuthenticationCeremony.Implementation.Models;

public class AuthenticationCeremonyParametersCookieContainer
{
    [JsonConstructor]
    public AuthenticationCeremonyParametersCookieContainer(string id, AuthenticationCeremonyParameters authenticationCeremonyParameters)
    {
        Id = id;
        AuthenticationCeremonyParameters = authenticationCeremonyParameters;
    }

    [JsonPropertyName("id")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Id { get; }

    [JsonPropertyName("authn")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public AuthenticationCeremonyParameters AuthenticationCeremonyParameters { get; }
}
