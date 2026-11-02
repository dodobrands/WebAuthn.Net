using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Configuration.Options.AttestationStatements;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusIngest;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models.Protocol.Json;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus;

/// <summary>
///     Provider of the <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a> of the Android attestation keys.
/// </summary>
public interface IAndroidKeyAttestationStatusProvider
{
    /// <summary>
    ///     Asynchronously downloads the status list and deserializes it.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>
    ///     If the status list was downloaded and matches its JSON format, the result contains <see cref="AndroidKeyAttestationStatusListJSON" />,
    ///     otherwise the result indicates that an error occurred during the download or the deserialization.
    /// </returns>
    Task<Result<AndroidKeyAttestationStatusListJSON>> DownloadStatusListAsync(CancellationToken cancellationToken);

    /// <summary>
    ///     Asynchronously loads the status list embedded in the application as a manifest resource of an assembly and deserializes it.
    /// </summary>
    /// <remarks>
    ///     <see cref="AndroidKeyAttestationStatusIngestBackgroundService" /> calls this method only if <see cref="AndroidKeyAttestationStatusListOptions.EmbeddedStatusList" /> is set. A provider that doesn't support
    ///     the status list embedded in the application throws <see cref="NotSupportedException" />: the exception is logged and counted, and the status list is only downloaded.
    /// </remarks>
    /// <param name="assembly">The assembly that contains the status list as a manifest resource.</param>
    /// <param name="resourceName">The name of the manifest resource that contains the status list exactly as Google serves it (JSON).</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>
    ///     If the status list was loaded and matches its JSON format, the result contains <see cref="AndroidKeyAttestationStatusListJSON" />,
    ///     otherwise the result indicates that an error occurred during the loading or the deserialization.
    /// </returns>
    /// <exception cref="NotSupportedException">The provider doesn't support the status list embedded in the application.</exception>
    Task<Result<AndroidKeyAttestationStatusListJSON>> LoadEmbeddedStatusListAsync(Assembly assembly, string resourceName, CancellationToken cancellationToken);
}
