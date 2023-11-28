using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.VerifyAssertion;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.VerifyAssertion;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Services.AuthenticationResponseDecoder;

/// <summary>
///     Service for decoding <see cref="AuthenticationResponseJSON" /> (<a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-pkcredential">PublicKeyCredential</a>) from a model suitable for JSON serialization into a typed representation suitable for further work.
/// </summary>
public interface IAuthenticationResponseDecoder
{
    /// <summary>
    ///     Decodes <see cref="AuthenticationResponseJSON" /> (<a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-pkcredential">PublicKeyCredential</a>) from a model suitable for JSON serialization into a typed representation suitable for further work.
    /// </summary>
    /// <param name="authenticationResponse"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#iface-pkcredential">PublicKeyCredential</a> serialized into JSON.</param>
    /// <returns>If decoding was successful, a result containing <see cref="AuthenticationResponse" />, otherwise, a result indicating that an error occurred during decoding.</returns>
    Result<AuthenticationResponse> Decode(AuthenticationResponseJSON authenticationResponse);
}
