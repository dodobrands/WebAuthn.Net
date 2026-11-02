using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models.Enums;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models;

/// <summary>
///     An entry of the <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a> of the Android attestation keys:
///     the status of a certificate that doesn't have a normal valid status.
/// </summary>
public class AndroidKeyAttestationStatusEntry
{
    /// <summary>
    ///     Constructs <see cref="AndroidKeyAttestationStatusEntry" />.
    /// </summary>
    /// <param name="status">The status of the certificate, or <see langword="null" /> if the entry has no status or a status that the library doesn't know.</param>
    /// <param name="reason">The reason for the status, or <see langword="null" /> if the entry has no reason or a reason that the library doesn't know.</param>
    public AndroidKeyAttestationStatusEntry(AndroidKeyAttestationRevocationStatus? status, AndroidKeyAttestationRevocationReason? reason)
    {
        Status = status;
        Reason = reason;
    }

    /// <summary>
    ///     The status of the certificate, or <see langword="null" /> if the entry has no status or a status that the library doesn't know.
    ///     The status list contains only the certificates that don't have a normal valid status, so every certificate in it is untrusted, whatever its status.
    /// </summary>
    public AndroidKeyAttestationRevocationStatus? Status { get; }

    /// <summary>
    ///     The reason for the status, or <see langword="null" /> if the entry has no reason or a reason that the library doesn't know.
    /// </summary>
    public AndroidKeyAttestationRevocationReason? Reason { get; }
}
