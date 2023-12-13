using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateOptions;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;

/// <summary>
///     The result of initiating the registration ceremony.
/// </summary>
public class BeginRegistrationCeremonyResult
{
    /// <summary>
    ///     Constructs <see cref="BeginRegistrationCeremonyResult" />.
    /// </summary>
    /// <param name="options">Model for serialization to JSON, containing the options necessary for performing the registration ceremony.</param>
    /// <param name="registrationCeremonyId">Unique identifier of the registration ceremony.</param>
    public BeginRegistrationCeremonyResult(PublicKeyCredentialCreationOptionsJSON options, string registrationCeremonyId)
    {
        Options = options;
        RegistrationCeremonyId = registrationCeremonyId;
    }

    /// <summary>
    ///     Model for serialization to JSON, containing the options necessary for performing the registration ceremony.
    /// </summary>
    public PublicKeyCredentialCreationOptionsJSON Options { get; }

    /// <summary>
    ///     Unique identifier of the registration ceremony.
    /// </summary>
    public string RegistrationCeremonyId { get; }
}
