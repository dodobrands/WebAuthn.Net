namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusProvider.Constants;

/// <summary>
///     The reasons why <see cref="DefaultAndroidKeyAttestationStatusProvider" /> doesn't provide the certificate revocation status list of the Android attestation keys embedded in the application. Each of them is reported with a Warning log entry and the
///     <c>webauthn.android_key.status_list.embedded.failures</c> counter (<see cref="Metrics.IAndroidKeyAttestationStatusCounters.IncrementEmbeddedFailure" />, tag <c>reason</c>).
/// </summary>
/// <remarks>
///     A status list embedded in the application that is not provided is not used: the status list is only downloaded.
///     <see cref="ResourceNotFound" /> points to the configuration of the application, <see cref="ListInvalid" /> to the content of the resource
///     (it has the same value as <see cref="AndroidKeyAttestationStatusDownloadFailures.ListInvalid" />).
/// </remarks>
public static class AndroidKeyAttestationStatusEmbeddedFailures
{
    /// <summary>
    ///     The assembly doesn't contain a manifest resource with the configured name.
    /// </summary>
    public const string ResourceNotFound = "resource_not_found";

    /// <summary>
    ///     The content of the resource doesn't match the documented JSON format of the status list: for example, it has no 'entries' object, or the status of an entry is not a string.
    /// </summary>
    public const string ListInvalid = AndroidKeyAttestationStatusDownloadFailures.ListInvalid;
}
