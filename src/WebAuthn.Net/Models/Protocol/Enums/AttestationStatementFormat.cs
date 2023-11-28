using System.Runtime.Serialization;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     Attestation statement format identifier
/// </summary>
/// <remarks>
///     <a href="https://www.iana.org/assignments/webauthn/webauthn.xhtml#webauthn-attestation-statement-format-ids">IANA "WebAuthn Attestation Statement Format Identifiers" registry</a>
/// </remarks>
public enum AttestationStatementFormat
{
    /// <summary>
    ///     The "packed" attestation statement format is a WebAuthn-optimized format for attestation. It uses a very compact but still extensible encoding method. This format is implementable by authenticators with limited resources (e.g., secure elements).
    /// </summary>
    [EnumMember(Value = "packed")]
    Packed = 0,

    /// <summary>
    ///     The TPM attestation statement format returns an attestation statement in the same format as the packed attestation statement format, although the rawData and signature fields are computed differently.
    /// </summary>
    [EnumMember(Value = "tpm")]
    Tpm = 1,

    /// <summary>
    ///     Platform authenticators on versions "N" (7.0), and later, may provide this proprietary "hardware attestation" statement.
    /// </summary>
    [EnumMember(Value = "android-key")]
    AndroidKey = 2,

    /// <summary>
    ///     Android-based platform authenticators MAY produce an attestation statement based on the Android SafetyNet API.
    /// </summary>
    [EnumMember(Value = "android-safetynet")]
    AndroidSafetyNet = 3,

    /// <summary>
    ///     Used with FIDO U2F authenticators
    /// </summary>
    [EnumMember(Value = "fido-u2f")]
    FidoU2F = 4,

    /// <summary>
    ///     Used with Apple devices' platform authenticators.
    /// </summary>
    [EnumMember(Value = "apple")]
    AppleAnonymous = 5,

    /// <summary>
    ///     Used to replace any authenticator-provided attestation statement when a WebAuthn Relying Party indicates it does not wish to receive attestation information.
    /// </summary>
    [EnumMember(Value = "none")]
    None = 6
}
