﻿using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models.Abstractions;

namespace WebAuthn.Net.Services.Common.AuthenticatorDataDecoder;

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
    Result<AbstractAuthenticatorData> Decode(byte[] rawAuthData);
}