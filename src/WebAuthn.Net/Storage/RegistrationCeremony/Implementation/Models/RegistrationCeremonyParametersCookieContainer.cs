using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using WebAuthn.Net.Storage.RegistrationCeremony.Models;

namespace WebAuthn.Net.Storage.RegistrationCeremony.Implementation.Models;

public class RegistrationCeremonyParametersCookieContainer
{
    [JsonConstructor]
    public RegistrationCeremonyParametersCookieContainer(string id, RegistrationCeremonyParameters registrationCeremonyParameters)
    {
        Id = id;
        RegistrationCeremonyParameters = registrationCeremonyParameters;
    }

    [JsonPropertyName("id")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Id { get; }

    [JsonPropertyName("reg")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public RegistrationCeremonyParameters RegistrationCeremonyParameters { get; }
}
