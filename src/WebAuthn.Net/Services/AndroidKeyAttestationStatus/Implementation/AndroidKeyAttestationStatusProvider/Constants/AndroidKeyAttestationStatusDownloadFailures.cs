namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusProvider.Constants;

/// <summary>
///     The reasons why <see cref="DefaultAndroidKeyAttestationStatusProvider" /> doesn't provide the downloaded certificate revocation status list of the Android attestation keys. Each of them is reported with a Warning log entry and the
///     <c>webauthn.android_key.status_list.download.failures</c> counter (<see cref="Metrics.IAndroidKeyAttestationStatusCounters.IncrementDownloadFailure" />, tag <c>reason</c>).
/// </summary>
public static class AndroidKeyAttestationStatusDownloadFailures
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
    ///     The status list doesn't match its documented JSON format: for example, it has no 'entries' object, or the status of an entry is not a string.
    /// </summary>
    public const string ListInvalid = "list_invalid";
}
