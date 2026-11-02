namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusIngest.Constants;

/// <summary>
///     The sources from which <see cref="AndroidKeyAttestationStatusIngestBackgroundService" /> loads the certificate revocation status list of the Android attestation keys. They are the values of the <c>source</c> tag of the
///     <c>webauthn.android_key.status_list.ingest.exceptions</c> counter (<see cref="Metrics.IAndroidKeyAttestationStatusCounters.IncrementIngestException" />).
/// </summary>
public static class AndroidKeyAttestationStatusListSources
{
    /// <summary>
    ///     The status list embedded in the application (<see cref="Configuration.Options.AttestationStatements.AndroidKeyAttestationStatusListOptions.EmbeddedStatusList" />), loaded at start-up.
    /// </summary>
    public const string Embedded = "embedded";

    /// <summary>
    ///     The status list downloaded from <see cref="Configuration.Options.AttestationStatements.AndroidKeyAttestationStatusListOptions.DownloadUri" />, at start-up and in the background.
    /// </summary>
    public const string Download = "download";
}
