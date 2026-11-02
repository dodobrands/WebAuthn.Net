using WebAuthn.Net.Models;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models.Protocol.Json;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus;

/// <summary>
///     Decoder of the <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a> of the Android attestation keys.
/// </summary>
public interface IAndroidKeyAttestationStatusDecoder
{
    /// <summary>
    ///     Decodes the status list into a typed representation.
    /// </summary>
    /// <remarks>
    ///     The entries of the status list are decoded independently of each other. The result indicates an error only if the status list has no entries object.
    /// </remarks>
    /// <param name="json">JSON model of the status list.</param>
    /// <returns>If decoding was successful, the result contains the <see cref="AndroidKeyAttestationStatusList" />, otherwise the result indicates that an error occurred.</returns>
    Result<AndroidKeyAttestationStatusList> Decode(AndroidKeyAttestationStatusListJSON json);
}
