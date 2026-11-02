using System.Threading;
using System.Threading.Tasks;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus;

/// <summary>
///     An HTTP client for downloading the <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a> of the Android attestation keys.
/// </summary>
public interface IAndroidKeyAttestationStatusHttpClient
{
    /// <summary>
    ///     Downloads the status list and returns its content as a string.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>A string containing the status list in JSON.</returns>
    Task<string> DownloadStatusListAsync(CancellationToken cancellationToken);
}
