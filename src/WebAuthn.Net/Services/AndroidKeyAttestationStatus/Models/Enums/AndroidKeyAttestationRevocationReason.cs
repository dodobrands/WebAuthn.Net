using System.Runtime.Serialization;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models.Enums;

/// <summary>
///     The reason for the status of a certificate in the <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a> of the Android attestation keys
///     (the 'reason' member of an entry).
/// </summary>
public enum AndroidKeyAttestationRevocationReason
{
    /// <summary>
    ///     The reason is not specified.
    /// </summary>
    [EnumMember(Value = "UNSPECIFIED")]
    Unspecified = 0,

    /// <summary>
    ///     The attestation key is compromised (for example, it was extracted from a device).
    /// </summary>
    [EnumMember(Value = "KEY_COMPROMISE")]
    KeyCompromise = 1,

    /// <summary>
    ///     The certificate authority that issued the certificate is compromised.
    /// </summary>
    [EnumMember(Value = "CA_COMPROMISE")]
    CaCompromise = 2,

    /// <summary>
    ///     The certificate is superseded by another one.
    /// </summary>
    [EnumMember(Value = "SUPERSEDED")]
    Superseded = 3,

    /// <summary>
    ///     A flaw in the software makes the attestation key untrustworthy.
    /// </summary>
    [EnumMember(Value = "SOFTWARE_FLAW")]
    SoftwareFlaw = 4
}
