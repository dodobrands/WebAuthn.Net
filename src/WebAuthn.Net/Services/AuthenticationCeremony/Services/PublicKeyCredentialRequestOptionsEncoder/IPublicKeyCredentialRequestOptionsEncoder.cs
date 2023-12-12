using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.CreateOptions;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.CreateOptions;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Services.PublicKeyCredentialRequestOptionsEncoder;

/// <summary>
///     Encoder for transforming <see cref="PublicKeyCredentialRequestOptions" /> into a model suitable for JSON serialization.
/// </summary>
public interface IPublicKeyCredentialRequestOptionsEncoder
{
    /// <summary>
    ///     Converts <see cref="PublicKeyCredentialRequestOptions" /> into a model suitable for serialization into JSON.
    /// </summary>
    /// <param name="options"><see cref="PublicKeyCredentialRequestOptions" /> that need to be converted into a model suitable for serialization into JSON.</param>
    /// <returns>Model suitable for serialization into JSON.</returns>
    PublicKeyCredentialRequestOptionsJSON Encode(PublicKeyCredentialRequestOptions options);
}
