using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.VerifyAssertion;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.VerifyAssertion;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Services.AuthenticationResponseDecoder;

/// <summary>
///     Decoder for <see cref="AuthenticationResponseJSON" /> (<a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-pkcredential">PublicKeyCredential</a>) from a model suitable for JSON serialization into a typed representation.
/// </summary>
public interface IAuthenticationResponseDecoder
{
    /// <summary>
    ///     Decodes <see cref="AuthenticationResponseJSON" /> (<a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-pkcredential">PublicKeyCredential</a>) from a model suitable for JSON serialization into a typed representation suitable for further work.
    /// </summary>
    /// <param name="authenticationResponse"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-pkcredential">PublicKeyCredential</a> model, suitable for serialization into JSON.</param>
    /// <returns>If the decoding was successful, the result contains the <see cref="AuthenticationResponse" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    Result<AuthenticationResponse> Decode(AuthenticationResponseJSON authenticationResponse);
}
