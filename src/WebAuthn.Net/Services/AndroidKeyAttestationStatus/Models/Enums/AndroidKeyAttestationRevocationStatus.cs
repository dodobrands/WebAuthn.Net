using System.Runtime.Serialization;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models.Enums;

/// <summary>
///     The status of a certificate in the <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a> of the Android attestation keys
///     (the 'status' member of an entry).
/// </summary>
/// <remarks>
///     The status list contains only the certificates that don't have a normal valid status, so a certificate in it is untrusted whatever its status.
/// </remarks>
public enum AndroidKeyAttestationRevocationStatus
{
    /// <summary>
    ///     The attestation key is revoked.
    /// </summary>
    [EnumMember(Value = "REVOKED")]
    Revoked = 0,

    /// <summary>
    ///     The attestation key is suspended.
    /// </summary>
    [EnumMember(Value = "SUSPENDED")]
    Suspended = 1
}
