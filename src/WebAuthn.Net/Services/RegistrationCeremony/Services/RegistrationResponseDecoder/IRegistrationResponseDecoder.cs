using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateCredential;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.RegistrationResponseDecoder;

/// <summary>
///     Decoder for <see cref="RegistrationResponseJSON" /> (<a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-pkcredential">PublicKeyCredential</a>) from a model suitable for JSON serialization to a typed representation.
/// </summary>
public interface IRegistrationResponseDecoder
{
    /// <summary>
    ///     Decodes <see cref="RegistrationResponseJSON" /> (<a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-pkcredential">PublicKeyCredential</a>) from from a model suitable for JSON serialization into a typed representation for further work.
    /// </summary>
    /// <param name="registrationResponse"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-pkcredential">PublicKeyCredential</a> model, suitable for serialization into JSON.</param>
    /// <returns>If the decoding was successful, the result contains the <see cref="RegistrationResponse" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    Result<RegistrationResponse> Decode(RegistrationResponseJSON registrationResponse);
}
