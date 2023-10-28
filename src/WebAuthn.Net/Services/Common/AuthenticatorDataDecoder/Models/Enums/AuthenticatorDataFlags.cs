using System;

namespace WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models.Enums;

/// <summary>
///     Flags that encode contextual bindings made by the authenticator.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-data">Web Authentication: An API for accessing Public Key Credentials Level 3 - §6.1. Authenticator Data</a>
/// </remarks>
[Flags]
public enum AuthenticatorDataFlags : byte
{
    /// <summary>
    ///     Bit 0: <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#concept-user-present">User Present</a> (UP) result
    /// </summary>
    UserPresent = 1 << 0,

    // Bit 1: Reserved for future use (RFU1).

    /// <summary>
    ///     Bit 2: <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#concept-user-verified">User Verified</a> (UV) result
    /// </summary>
    UserVerified = 1 << 2,

    /// <summary>
    ///     Bit 3: <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#backup-eligibility">Backup Eligibility</a> (BE)
    /// </summary>
    BackupEligibility = 1 << 3,

    /// <summary>
    ///     Bit 4: <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#backup-state">Backup State</a> (BS)
    /// </summary>
    BackupState = 1 << 4,

    // Bit 5: Reserved for future use (RFU2).

    /// <summary>
    ///     Bit 6: <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attested-credential-data">Attested credential data</a> included (AT).
    /// </summary>
    AttestedCredentialData = 1 << 6,

    /// <summary>
    ///     Bit 7: Extension data included (ED).
    /// </summary>
    ExtensionDataIncluded = 1 << 7
}
