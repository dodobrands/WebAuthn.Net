using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models.Abstractions;

namespace WebAuthn.Net.Services.Common.AuthenticatorDataDecoder;

/// <summary>
///     Decoder for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> from binary into a typed representation.
/// </summary>
public interface IAuthenticatorDataDecoder
{
    /// <summary>
    ///     Decodes the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a> from binary representation to a typed format for further processing.
    /// </summary>
    /// <param name="rawAuthData">Binary representation of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-data">authenticator data</a>.</param>
    /// <returns>If the decoding was successful, the result contains the <see cref="AbstractAuthenticatorData" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    Result<AbstractAuthenticatorData> Decode(byte[] rawAuthData);
}
