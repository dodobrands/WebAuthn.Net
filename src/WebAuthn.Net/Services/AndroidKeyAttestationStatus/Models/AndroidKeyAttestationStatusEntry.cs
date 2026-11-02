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
    /// <param name="status">The current status of the certificate (REVOKED or SUSPENDED, or another value), or <see langword="null" /> if the entry has no status.</param>
    /// <param name="reason">The reason for the current status (UNSPECIFIED, KEY_COMPROMISE, CA_COMPROMISE, SUPERSEDED or SOFTWARE_FLAW, or another value), or <see langword="null" /> if the entry has no reason.</param>
    public AndroidKeyAttestationStatusEntry(string? status, string? reason)
    {
        Status = status;
        Reason = reason;
    }

    /// <summary>
    ///     The current status of the certificate (REVOKED or SUSPENDED, or another value), or <see langword="null" /> if the entry has no status.
    ///     The status list contains only the certificates that don't have a normal valid status, so every certificate in it is untrusted, whatever its status.
    /// </summary>
    public string? Status { get; }

    /// <summary>
    ///     The reason for the current status (UNSPECIFIED, KEY_COMPROMISE, CA_COMPROMISE, SUPERSEDED or SOFTWARE_FLAW, or another value), or <see langword="null" /> if the entry has no reason.
    /// </summary>
    public string? Reason { get; }
}
