using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus;

/// <summary>
///     The ingestion service for the <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a> of the Android attestation keys,
///     designed to store the status list that is in use.
/// </summary>
public interface IAndroidKeyAttestationStatusIngestService
{
    /// <summary>
    ///     Upserts the downloaded status list.
    /// </summary>
    /// <param name="statusList">The status list.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    Task UpsertAsync(
        AndroidKeyAttestationStatusList statusList,
        CancellationToken cancellationToken);

    /// <summary>
    ///     Upserts the status list embedded in the application, which is loaded at start-up before the status list is downloaded.
    /// </summary>
    /// <remarks>
    ///     The embedded status list is a fallback for the case when the status list can't be downloaded, so it is expected to be older than the status list in use, if there is any
    ///     (for example, a persistent storage keeps the status list downloaded before the restart of the application). The default implementation of this interface method upserts it the same way as <see cref="UpsertAsync" />.
    /// </remarks>
    /// <param name="statusList">The status list.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    Task UpsertEmbeddedAsync(
        AndroidKeyAttestationStatusList statusList,
        CancellationToken cancellationToken)
    {
        return UpsertAsync(statusList, cancellationToken);
    }
}
