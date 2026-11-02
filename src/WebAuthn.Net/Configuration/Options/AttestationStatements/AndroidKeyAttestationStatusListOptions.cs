using System;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusIngest;

namespace WebAuthn.Net.Configuration.Options.AttestationStatements;

/// <summary>
///     Options of the <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a> that Google publishes for the Android attestation keys.
///     The certificates of every "Android Key" attestation statement are checked against it.
/// </summary>
/// <remarks>
///     <para>
///         The status list is loaded by <see cref="AndroidKeyAttestationStatusIngestBackgroundService" />: at start-up, the status list embedded in the application (<see cref="EmbeddedStatusList" />), if it is configured,
///         and then the status list downloaded from <see cref="DownloadUri" />. Once it is downloaded, the next refresh takes place after <see cref="IngestInterval" />,
///         and after an unsuccessful attempt the next attempt takes place after <see cref="RetryInterval" />.
///     </para>
///     <para>
///         If the status list embedded in the application is loaded, the start of the application doesn't wait for the download: the status list is downloaded in the background right away.
///         Otherwise, the start of the application waits for the first attempt to download it. While no status list is available, every "Android Key" attestation statement is rejected.
///     </para>
/// </remarks>
public class AndroidKeyAttestationStatusListOptions
{
    /// <summary>
    ///     The address from where to download the status list. The default is <c>https://android.googleapis.com/attestation/status</c>, where Google publishes it.
    /// </summary>
    public Uri DownloadUri { get; set; } = new("https://android.googleapis.com/attestation/status", UriKind.Absolute);

    /// <summary>
    ///     The maximum size of the response body (the status list) in bytes that the client agrees to download from <see cref="DownloadUri" />. The default is 16 MiB (16777216 bytes).
    /// </summary>
    /// <remarks>
    ///     The download is aborted as soon as the body exceeds this size, regardless of the 'Content-Length' header, to protect the application from a hostile or compromised endpoint.
    ///     For comparison, the status list published by Google in October 2026 (1769 entries) is about 180 KB.
    /// </remarks>
    public long MaxResponseSizeInBytes { get; set; } = 16L * 1024 * 1024;

    /// <summary>
    ///     The time limit for the whole download of the status list from <see cref="DownloadUri" />: from sending the request to reading the last byte of the response body. The default is 1 minute.
    /// </summary>
    /// <remarks>
    ///     A hostile endpoint that sends the body slowly can't make the download (and the start of the application, which awaits the first download unless a status list is already available) hang indefinitely.
    ///     <see cref="System.Net.Http.HttpClient.Timeout" /> doesn't replace it: it covers only the time until the response headers are received, because the body is read as a stream.
    /// </remarks>
    public TimeSpan DownloadTimeout { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    ///     The interval between the refreshes of the status list after it has been downloaded. The default is 1 day (24 hours): Google serves the status list with
    ///     <c>Cache-Control: max-age=86400</c>, and <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">documents</a> that this header determines how often to check for updates.
    /// </summary>
    /// <remarks>
    ///     A value that is not positive is not used: the default value is used instead, and an error is logged.
    /// </remarks>
    public TimeSpan IngestInterval { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    ///     The interval between the attempts to download the status list after an unsuccessful attempt (the status list can't be downloaded or decoded, or an exception occurred).
    ///     The attempts are repeated with this interval until the status list is downloaded, after which it is refreshed every <see cref="IngestInterval" />. The default is 1 minute.
    /// </summary>
    /// <remarks>
    ///     A value that is not positive is not used: the default value is used instead, and an error is logged.
    /// </remarks>
    public TimeSpan RetryInterval { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    ///     The status list embedded in the application: the assembly and the name of its manifest resource that contains the status list.
    ///     Defaults to <see langword="null" />: no status list is embedded in the application.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         The embedded status list is loaded at start-up before the download, so that "Android Key" attestation statements can be verified even if <see cref="DownloadUri" /> is unavailable.
    ///         The status list downloaded from <see cref="DownloadUri" /> replaces it as soon as it is downloaded. If the embedded status list can't be loaded, the reason is logged and counted,
    ///         and the status list is downloaded from <see cref="DownloadUri" /> only.
    ///     </para>
    ///     <para>
    ///         The embedded status list has to be the JSON exactly as Google serves it. It isn't signed: like the downloaded one, it is trusted as it is.
    ///     </para>
    /// </remarks>
    public AndroidKeyAttestationEmbeddedStatusListOptions? EmbeddedStatusList { get; set; }
}
