using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.CreateOptions;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;

/// <summary>
///     The result of initiating the authentication ceremony.
/// </summary>
public class BeginAuthenticationCeremonyResult
{
    /// <summary>
    ///     Constructs <see cref="BeginAuthenticationCeremonyResult" />.
    /// </summary>
    /// <param name="options">Model for serialization to JSON, containing the options necessary for performing the authentication ceremony.</param>
    /// <param name="authenticationCeremonyId">Unique identifier of the authentication ceremony.</param>
    public BeginAuthenticationCeremonyResult(PublicKeyCredentialRequestOptionsJSON options, string authenticationCeremonyId)
    {
        Options = options;
        AuthenticationCeremonyId = authenticationCeremonyId;
    }

    /// <summary>
    ///     Model for serialization to JSON, containing the options necessary for performing the authentication ceremony.
    /// </summary>
    public PublicKeyCredentialRequestOptionsJSON Options { get; }

    /// <summary>
    ///     Unique identifier of the authentication ceremony.
    /// </summary>
    public string AuthenticationCeremonyId { get; }
}
