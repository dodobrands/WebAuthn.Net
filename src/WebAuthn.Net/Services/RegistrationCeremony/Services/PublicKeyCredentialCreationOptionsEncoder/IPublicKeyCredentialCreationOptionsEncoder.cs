using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateOptions;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.PublicKeyCredentialCreationOptionsEncoder;

/// <summary>
///     Encoder for transforming <see cref="PublicKeyCredentialCreationOptions" /> into a model suitable for JSON serialization.
/// </summary>
public interface IPublicKeyCredentialCreationOptionsEncoder
{
    /// <summary>
    ///     Converts <see cref="PublicKeyCredentialCreationOptions" /> into a model suitable for JSON serialization.
    /// </summary>
    /// <param name="options"><see cref="PublicKeyCredentialCreationOptions" /> that need to be converted into a model suitable for JSON serialization.</param>
    /// <returns>Model suitable for JSON serialization.</returns>
    PublicKeyCredentialCreationOptionsJSON Encode(PublicKeyCredentialCreationOptions options);
}
