using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Abstractions;

/// <summary>
///     Service for working with <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> structure.
/// </summary>
public interface IAuthenticatorDataDecoder
{
    /// <summary>
    ///     Returns a typed representation of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> structure.
    /// </summary>
    /// <param name="rawAuthData">The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> structure encoded in binary format.</param>
    /// <returns>The result of the operation, containing either an error or the decoded value.</returns>
    Result<AuthenticatorData> Decode(byte[] rawAuthData);
}
