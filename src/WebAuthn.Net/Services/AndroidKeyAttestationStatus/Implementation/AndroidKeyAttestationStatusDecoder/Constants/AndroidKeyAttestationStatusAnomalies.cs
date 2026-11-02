namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusDecoder.Constants;

/// <summary>
///     The anomalies that <see cref="DefaultAndroidKeyAttestationStatusDecoder" /> reports with a Warning log entry and the
///     <c>webauthn.android_key.status_list.decode.anomalies</c> counter (<see cref="Metrics.IAndroidKeyAttestationStatusCounters.IncrementDecodeAnomaly" />).
/// </summary>
public static class AndroidKeyAttestationStatusAnomalies
{
    /// <summary>
    ///     Rejected: the key of an entry is not a serial number in hexadecimal, so no certificate can match it, and the entry is skipped.
    /// </summary>
    public const string KeyInvalid = "key.invalid";

    /// <summary>
    ///     Rejected: the key of an entry names the same serial number as the key of an earlier entry (they differ only in case or leading zeros), so the entry is skipped.
    ///     The certificate is still in the status list through the earlier entry, so it is untrusted.
    /// </summary>
    public const string KeyDuplicate = "key.duplicate";

    /// <summary>
    ///     Tolerated: the key of an entry is a serial number in hexadecimal, but not in lowercase without leading zeros, as the status list documents it. The entry is kept under the normalized key.
    /// </summary>
    public const string KeyNotCanonical = "key.not_canonical";

    /// <summary>
    ///     Tolerated: an entry has no status (the entry is null, or its 'status' member is absent, null or empty). The entry is kept without a status: the certificate is still in the status list, so it is untrusted.
    /// </summary>
    public const string StatusMissing = "status.missing";

    /// <summary>
    ///     Tolerated: the status of an entry is neither REVOKED nor SUSPENDED. The entry is kept without a status: the certificate is still in the status list, so it is untrusted.
    /// </summary>
    public const string StatusUnknown = "status.unknown";

    /// <summary>
    ///     Tolerated: the reason of an entry is none of UNSPECIFIED, KEY_COMPROMISE, CA_COMPROMISE, SUPERSEDED and SOFTWARE_FLAW. The entry is kept without a reason.
    /// </summary>
    public const string ReasonUnknown = "reason.unknown";
}
