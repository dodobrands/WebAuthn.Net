using WebAuthn.Net.Services.AuthenticatorData.Models;

namespace WebAuthn.Net.Services.AuthenticatorData;

/// <summary>
///     Service for working with <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> structure.
/// </summary>
public interface IAuthenticatorDataService
{
    /// <summary>
    ///     Returns a typed representation of the <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> structure.
    /// </summary>
    /// <param name="encodedAuthenticatorData">The <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> structure encoded in binary format.</param>
    /// <returns>Typed representation of the authenticator data structure.</returns>
    AuthenticatorDataPayload GetAuthenticatorData(byte[] encodedAuthenticatorData);
}
