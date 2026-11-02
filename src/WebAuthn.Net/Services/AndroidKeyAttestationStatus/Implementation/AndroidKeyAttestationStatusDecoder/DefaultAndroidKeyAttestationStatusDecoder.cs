using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusDecoder.Constants;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models.Enums;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models.Protocol.Json;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusDecoder;

/// <summary>
///     Default implementation of <see cref="IAndroidKeyAttestationStatusDecoder" />.
/// </summary>
/// <remarks>
///     The provider of the status list has checked that it matches its <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">documented JSON format</a>.
///     An entry is dropped only if it can't name a certificate or an earlier entry names the same certificate: the status list contains only the certificates that don't have a normal valid status,
///     so a dropped entry would let its certificate pass. Every anomaly of an entry is logged and counted (<see cref="AndroidKeyAttestationStatusAnomalies" />).
/// </remarks>
public class DefaultAndroidKeyAttestationStatusDecoder : IAndroidKeyAttestationStatusDecoder
{
    // A key, a status or a reason from the status list is logged with at most this number of characters.
    private const int MaxLoggedValueLength = 64;

    /// <summary>
    ///     Constructs <see cref="DefaultAndroidKeyAttestationStatusDecoder" />.
    /// </summary>
    /// <param name="serialNumberFormatter">Formatter of the serial numbers in the form of the keys of the status list, used to normalize the keys.</param>
    /// <param name="statusSerializer">Serializer for the <see cref="AndroidKeyAttestationRevocationStatus" /> enum.</param>
    /// <param name="reasonSerializer">Serializer for the <see cref="AndroidKeyAttestationRevocationReason" /> enum.</param>
    /// <param name="counters">Counters for the metrics of the status list, used to count the anomalies of its entries.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultAndroidKeyAttestationStatusDecoder(
        IAndroidKeyAttestationStatusSerialNumberFormatter serialNumberFormatter,
        IEnumMemberAttributeSerializer<AndroidKeyAttestationRevocationStatus> statusSerializer,
        IEnumMemberAttributeSerializer<AndroidKeyAttestationRevocationReason> reasonSerializer,
        IAndroidKeyAttestationStatusCounters counters,
        ILogger<DefaultAndroidKeyAttestationStatusDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(serialNumberFormatter);
        ArgumentNullException.ThrowIfNull(statusSerializer);
        ArgumentNullException.ThrowIfNull(reasonSerializer);
        ArgumentNullException.ThrowIfNull(counters);
        ArgumentNullException.ThrowIfNull(logger);
        SerialNumberFormatter = serialNumberFormatter;
        StatusSerializer = statusSerializer;
        ReasonSerializer = reasonSerializer;
        Counters = counters;
        Logger = logger;
    }

    /// <summary>
    ///     Formatter of the serial numbers in the form of the keys of the status list, used to normalize the keys.
    /// </summary>
    protected IAndroidKeyAttestationStatusSerialNumberFormatter SerialNumberFormatter { get; }

    /// <summary>
    ///     Serializer for the <see cref="AndroidKeyAttestationRevocationStatus" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<AndroidKeyAttestationRevocationStatus> StatusSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="AndroidKeyAttestationRevocationReason" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<AndroidKeyAttestationRevocationReason> ReasonSerializer { get; }

    /// <summary>
    ///     Counters for the metrics of the status list, used to count the anomalies of its entries.
    /// </summary>
    protected IAndroidKeyAttestationStatusCounters Counters { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultAndroidKeyAttestationStatusDecoder> Logger { get; }

    /// <inheritdoc />
    public virtual Result<AndroidKeyAttestationStatusList> Decode(AndroidKeyAttestationStatusListJSON json)
    {
        ArgumentNullException.ThrowIfNull(json);
        var entriesJson = json.Entries;
        if (entriesJson is null)
        {
            Logger.WarnStatusListEntriesMissing();
            return Result<AndroidKeyAttestationStatusList>.Fail();
        }

        var entries = new Dictionary<string, AndroidKeyAttestationStatusEntry>(entriesJson.Count, StringComparer.Ordinal);
        foreach (var (key, entryJson) in entriesJson)
        {
            if (!SerialNumberFormatter.TryNormalize(key, out var serialNumber))
            {
                Logger.WarnEntryKeyInvalid(LogValue.Sanitize(key, MaxLoggedValueLength));
                Counters.IncrementDecodeAnomaly(AndroidKeyAttestationStatusAnomalies.KeyInvalid, false);
                continue;
            }

            // the keys of the entries differ, so only a key in another case or with leading zeros can name the certificate of an earlier entry
            if (entries.ContainsKey(serialNumber))
            {
                Logger.WarnEntryKeyDuplicate(LogValue.Sanitize(key, MaxLoggedValueLength), serialNumber);
                Counters.IncrementDecodeAnomaly(AndroidKeyAttestationStatusAnomalies.KeyDuplicate, false);
                continue;
            }

            if (!string.Equals(serialNumber, key, StringComparison.Ordinal))
            {
                Logger.WarnEntryKeyNotCanonical(LogValue.Sanitize(key, MaxLoggedValueLength), serialNumber);
                Counters.IncrementDecodeAnomaly(AndroidKeyAttestationStatusAnomalies.KeyNotCanonical, true);
            }

            entries.Add(serialNumber, DecodeEntry(serialNumber, entryJson));
        }

        return Result<AndroidKeyAttestationStatusList>.Success(new(entries));
    }

    /// <summary>
    ///     Decodes an entry of the status list.
    /// </summary>
    /// <remarks>
    ///     An entry without a status, or with a status other than REVOKED and SUSPENDED, is kept without a status: the certificate is in the status list, so it is untrusted.
    ///     A reason other than the documented ones is dropped, because it only explains the status. Every such anomaly is logged and counted.
    /// </remarks>
    /// <param name="serialNumber">The serial number of the certificate of the entry, normalized.</param>
    /// <param name="entryJson">The entry, or <see langword="null" /> if its value is <see langword="null" />.</param>
    /// <returns>The decoded entry.</returns>
    protected virtual AndroidKeyAttestationStatusEntry DecodeEntry(string serialNumber, AndroidKeyAttestationStatusEntryJSON? entryJson)
    {
        return new(DecodeStatus(serialNumber, entryJson?.Status), DecodeReason(serialNumber, entryJson?.Reason));
    }

    private AndroidKeyAttestationRevocationStatus? DecodeStatus(string serialNumber, string? status)
    {
        if (string.IsNullOrEmpty(status))
        {
            Logger.WarnEntryStatusMissing(serialNumber);
            Counters.IncrementDecodeAnomaly(AndroidKeyAttestationStatusAnomalies.StatusMissing, true);
            return null;
        }

        if (!StatusSerializer.TryDeserialize(status, out var result))
        {
            Logger.WarnEntryStatusUnknown(serialNumber, LogValue.Sanitize(status, MaxLoggedValueLength));
            Counters.IncrementDecodeAnomaly(AndroidKeyAttestationStatusAnomalies.StatusUnknown, true);
            return null;
        }

        return result;
    }

    private AndroidKeyAttestationRevocationReason? DecodeReason(string serialNumber, string? reason)
    {
        // the reason is optional
        if (reason is null)
        {
            return null;
        }

        if (!ReasonSerializer.TryDeserialize(reason, out var result))
        {
            Logger.WarnEntryReasonUnknown(serialNumber, LogValue.Sanitize(reason, MaxLoggedValueLength));
            Counters.IncrementDecodeAnomaly(AndroidKeyAttestationStatusAnomalies.ReasonUnknown, true);
            return null;
        }

        return result;
    }
}

/// <summary>
///     Extension methods for logging the decoding of the certificate revocation status list of the Android attestation keys.
/// </summary>
public static partial class DefaultAndroidKeyAttestationStatusDecoderLoggingExtensions
{
    /// <summary>
    ///     The status list of the Android attestation keys has no 'entries' object
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The status list of the Android attestation keys has no 'entries' object")]
    public static partial void WarnStatusListEntriesMissing(this ILogger logger);

    /// <summary>
    ///     The entry '{Key}' of the status list of the Android attestation keys was skipped because its key is not a serial number in hexadecimal
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="key">The key of the entry, sanitized.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The entry '{Key}' of the status list of the Android attestation keys was skipped because its key is not a serial number in hexadecimal")]
    public static partial void WarnEntryKeyInvalid(this ILogger logger, string key);

    /// <summary>
    ///     The entry '{Key}' of the status list of the Android attestation keys was skipped because an earlier entry has the same serial number '{SerialNumber}'
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="key">The key of the entry, sanitized.</param>
    /// <param name="serialNumber">The normalized serial number of the earlier entry.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The entry '{Key}' of the status list of the Android attestation keys was skipped because an earlier entry has the same serial number '{SerialNumber}'")]
    public static partial void WarnEntryKeyDuplicate(this ILogger logger, string key, string serialNumber);

    /// <summary>
    ///     The key '{Key}' of the status list of the Android attestation keys is not in lowercase hexadecimal without leading zeros, so its entry is kept under the serial number '{SerialNumber}'
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="key">The key of the entry, sanitized.</param>
    /// <param name="serialNumber">The normalized serial number under which the entry is kept.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The key '{Key}' of the status list of the Android attestation keys is not in lowercase hexadecimal without leading zeros, so its entry is kept under the serial number '{SerialNumber}'")]
    public static partial void WarnEntryKeyNotCanonical(this ILogger logger, string key, string serialNumber);

    /// <summary>
    ///     The entry for the certificate with the serial number '{SerialNumber}' in the status list of the Android attestation keys has no status, so the certificate is untrusted
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="serialNumber">The serial number of the certificate of the entry.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The entry for the certificate with the serial number '{SerialNumber}' in the status list of the Android attestation keys has no status, so the certificate is untrusted")]
    public static partial void WarnEntryStatusMissing(this ILogger logger, string serialNumber);

    /// <summary>
    ///     The entry for the certificate with the serial number '{SerialNumber}' in the status list of the Android attestation keys has the unknown status '{Status}', so the certificate is untrusted
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="serialNumber">The serial number of the certificate of the entry.</param>
    /// <param name="status">The status of the entry, sanitized.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The entry for the certificate with the serial number '{SerialNumber}' in the status list of the Android attestation keys has the unknown status '{Status}', so the certificate is untrusted")]
    public static partial void WarnEntryStatusUnknown(this ILogger logger, string serialNumber, string status);

    /// <summary>
    ///     The entry for the certificate with the serial number '{SerialNumber}' in the status list of the Android attestation keys has the unknown reason '{Reason}', so the reason is ignored
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="serialNumber">The serial number of the certificate of the entry.</param>
    /// <param name="reason">The reason of the entry, sanitized.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The entry for the certificate with the serial number '{SerialNumber}' in the status list of the Android attestation keys has the unknown reason '{Reason}', so the reason is ignored")]
    public static partial void WarnEntryReasonUnknown(this ILogger logger, string serialNumber, string reason);
}
