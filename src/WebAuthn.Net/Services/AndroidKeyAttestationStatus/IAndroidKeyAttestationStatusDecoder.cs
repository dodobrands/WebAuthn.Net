using WebAuthn.Net.Models;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus;

/// <summary>
///     Decoder of the <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a> of the Android attestation keys.
/// </summary>
public interface IAndroidKeyAttestationStatusDecoder
{
    /// <summary>
    ///     Decodes the status list.
    /// </summary>
    /// <param name="json">The status list in JSON, as Google serves it.</param>
    /// <returns>If the status list was decoded, the result contains it, otherwise the result indicates that the status list is malformed.</returns>
    Result<AndroidKeyAttestationStatusList> Decode(string json);
}
