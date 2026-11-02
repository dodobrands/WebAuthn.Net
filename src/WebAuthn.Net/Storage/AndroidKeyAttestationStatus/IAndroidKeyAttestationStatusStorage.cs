using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models;

namespace WebAuthn.Net.Storage.AndroidKeyAttestationStatus;

/// <summary>
///     Storage of the <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a> of the Android attestation keys
///     that is in use.
/// </summary>
public interface IAndroidKeyAttestationStatusStorage
{
    /// <summary>
    ///     Returns the status list in use.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>The status list in use, or <see langword="null" /> if no status list has been stored yet.</returns>
    Task<AndroidKeyAttestationStatusList?> GetAsync(CancellationToken cancellationToken);

    /// <summary>
    ///     Replaces the status list in use.
    /// </summary>
    /// <param name="statusList">The status list to use from now on.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    Task UpsertAsync(AndroidKeyAttestationStatusList statusList, CancellationToken cancellationToken);
}
