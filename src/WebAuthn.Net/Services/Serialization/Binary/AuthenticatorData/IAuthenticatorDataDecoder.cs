using System;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Binary.AuthenticatorData.Models;

namespace WebAuthn.Net.Services.Serialization.Binary.AuthenticatorData;

/// <summary>
///     Service for working with <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> structure.
/// </summary>
public interface IAuthenticatorDataDecoder
{
    /// <summary>
    ///     Returns a typed representation of the <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> structure.
    /// </summary>
    /// <param name="authenticatorData">The <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> structure encoded in binary format.</param>
    /// <returns>The result of the operation, containing either an error or the decoded value.</returns>
    Result<DecodedAuthenticatorData> Decode(ReadOnlySpan<byte> authenticatorData);
}
