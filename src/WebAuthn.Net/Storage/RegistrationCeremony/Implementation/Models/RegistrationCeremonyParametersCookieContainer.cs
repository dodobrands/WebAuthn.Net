using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using WebAuthn.Net.Storage.RegistrationCeremony.Models;

namespace WebAuthn.Net.Storage.RegistrationCeremony.Implementation.Models;

/// <summary>
///     Container for registration ceremony data.
/// </summary>
public class RegistrationCeremonyParametersCookieContainer
{
    /// <summary>
    ///     Constructs <see cref="RegistrationCeremonyParametersCookieContainer" />.
    /// </summary>
    /// <param name="id">Unique identifier for the registration ceremony.</param>
    /// <param name="registrationCeremonyParameters">Registration ceremony parameters.</param>
    [JsonConstructor]
    public RegistrationCeremonyParametersCookieContainer(
        string id,
        RegistrationCeremonyParameters registrationCeremonyParameters)
    {
        Id = id;
        RegistrationCeremonyParameters = registrationCeremonyParameters;
    }

    /// <summary>
    ///     Unique identifier for the registration ceremony.
    /// </summary>
    [JsonPropertyName("id")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Id { get; }

    /// <summary>
    ///     Registration ceremony parameters.
    /// </summary>
    [JsonPropertyName("reg")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public RegistrationCeremonyParameters RegistrationCeremonyParameters { get; }
}
