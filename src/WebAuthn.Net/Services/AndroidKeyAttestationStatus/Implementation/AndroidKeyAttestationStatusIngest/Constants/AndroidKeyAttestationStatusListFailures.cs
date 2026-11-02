namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusIngest.Constants;

/// <summary>
///     The reasons why <see cref="AndroidKeyAttestationStatusIngestBackgroundService" /> couldn't load the certificate revocation status list of the Android attestation keys. They are the values of the <c>reason</c> tag of the
///     <c>webauthn.android_key.status_list.download.failures</c> and <c>webauthn.android_key.status_list.embedded.failures</c> counters
///     (<see cref="Metrics.IAndroidKeyAttestationStatusCounters.IncrementDownloadFailure" />, <see cref="Metrics.IAndroidKeyAttestationStatusCounters.IncrementEmbeddedFailure" />).
/// </summary>
public static class AndroidKeyAttestationStatusListFailures
{
    /// <summary>
    ///     The request failed, the response has an unsuccessful status code or exceeds the maximum allowed size, or the connection was broken.
    /// </summary>
    public const string RequestFailed = "request_failed";

    /// <summary>
    ///     The download wasn't completed within its time limit.
    /// </summary>
    public const string Timeout = "timeout";

    /// <summary>
    ///     The assembly doesn't contain the manifest resource of the status list embedded in the application.
    /// </summary>
    public const string ResourceNotFound = "resource_not_found";

    /// <summary>
    ///     The status list is malformed: it is not a JSON object with an 'entries' object.
    /// </summary>
    public const string ListInvalid = "list_invalid";
}
