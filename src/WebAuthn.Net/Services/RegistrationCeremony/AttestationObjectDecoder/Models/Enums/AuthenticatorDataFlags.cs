using System;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.Enums;

/// <summary>
///     Flags that encode contextual bindings made by the authenticator.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">Web Authentication: An API for accessing Public Key Credentials Level 3 - §6.1. Authenticator Data</a>
/// </remarks>
[Flags]
public enum AuthenticatorDataFlags : byte
{
    // bits are enumerated from zero

    /// <summary>
    ///     Bit 0: <a href="https://www.w3.org/TR/webauthn-3/#concept-user-present">User Present</a> (<a href="https://www.w3.org/TR/webauthn-3/#up">UP</a>) result.
    ///     Means the user is <a href="https://www.w3.org/TR/webauthn-3/#concept-user-present">present</a>.
    /// </summary>
    UserPresent = 0b0000_0001,

    // Bit 1: Reserved for future use (RFU1).

    /// <summary>
    ///     Bit 2: <a href="https://www.w3.org/TR/webauthn-3/#concept-user-verified">User Verified</a> (<a href="https://www.w3.org/TR/webauthn-3/#uv">UV</a>) result.
    /// </summary>
    UserVerified = 0b0000_0100,

    // Bits 3-5: Reserved for future use (RFU2).

    /// <summary>
    ///     Bit 6: <a href="https://www.w3.org/TR/webauthn-3/#attested-credential-data">Attested credential data</a> included (AT).
    ///     Indicates whether the authenticator added <a href="https://www.w3.org/TR/webauthn-3/#attested-credential-data">attested credential data</a>.
    /// </summary>
    AttestedCredentialData = 0b0100_0000,

    /// <summary>
    ///     Bit 7: Extension data included (ED). Indicates if the <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> has <a href="https://www.w3.org/TR/webauthn-3/#authdataextensions">extensions</a>.
    /// </summary>
    ExtensionDataIncluded = 0b1000_0000
}
