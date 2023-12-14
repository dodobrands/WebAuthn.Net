using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using WebAuthn.Net.Storage.AuthenticationCeremony.Models;

namespace WebAuthn.Net.Storage.AuthenticationCeremony.Implementation.Models;

/// <summary>
///     Container for authentication ceremony data.
/// </summary>
public class AuthenticationCeremonyParametersCookieContainer
{
    /// <summary>
    ///     Constructs <see cref="AuthenticationCeremonyParametersCookieContainer" />.
    /// </summary>
    /// <param name="id">Unique identifier for the authentication ceremony.</param>
    /// <param name="authenticationCeremonyParameters">Authentication ceremony parameters.</param>
    [JsonConstructor]
    public AuthenticationCeremonyParametersCookieContainer(
        string id,
        AuthenticationCeremonyParameters authenticationCeremonyParameters)
    {
        Id = id;
        AuthenticationCeremonyParameters = authenticationCeremonyParameters;
    }

    /// <summary>
    ///     Unique identifier for the authentication ceremony.
    /// </summary>
    [JsonPropertyName("id")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Id { get; }

    /// <summary>
    ///     Authentication ceremony parameters.
    /// </summary>
    [JsonPropertyName("authn")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public AuthenticationCeremonyParameters AuthenticationCeremonyParameters { get; }
}
