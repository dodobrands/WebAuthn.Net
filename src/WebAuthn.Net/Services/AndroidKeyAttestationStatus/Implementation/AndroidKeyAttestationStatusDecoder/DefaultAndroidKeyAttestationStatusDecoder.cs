using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusDecoder.Constants;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models.Protocol.Json;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusDecoder;

/// <summary>
///     Default implementation of <see cref="IAndroidKeyAttestationStatusDecoder" />.
/// </summary>
/// <remarks>
///     The provider of the status list has checked that it matches its <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">documented JSON format</a>.
///     An entry is never dropped while it can still name a certificate: the status list contains only the certificates that don't have a normal valid status,
///     so a dropped entry would let its certificate pass. Every anomaly of an entry is logged and counted (<see cref="AndroidKeyAttestationStatusAnomalies" />).
/// </remarks>
public class DefaultAndroidKeyAttestationStatusDecoder : IAndroidKeyAttestationStatusDecoder
{
    // The values of the 'status' member that the status list documents.
    private const string StatusRevoked = "REVOKED";
    private const string StatusSuspended = "SUSPENDED";

    // A key or a status from the status list is logged with at most this number of characters.
    private const int MaxLoggedValueLength = 64;

    /// <summary>
    ///     Constructs <see cref="DefaultAndroidKeyAttestationStatusDecoder" />.
    /// </summary>
    /// <param name="counters">Counters for the metrics of the status list, used to count the anomalies of its entries.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultAndroidKeyAttestationStatusDecoder(
        IAndroidKeyAttestationStatusCounters counters,
        ILogger<DefaultAndroidKeyAttestationStatusDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(counters);
        ArgumentNullException.ThrowIfNull(logger);
        Counters = counters;
        Logger = logger;
    }

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
            var serialNumber = NormalizeSerialNumber(key);
            if (serialNumber is null)
            {
                Logger.WarnEntryKeyInvalid(LogValue.Sanitize(key, MaxLoggedValueLength));
                Counters.IncrementDecodeAnomaly(AndroidKeyAttestationStatusAnomalies.KeyInvalid, false);
                continue;
            }

            if (!string.Equals(serialNumber, key, StringComparison.Ordinal))
            {
                Logger.WarnEntryKeyNotCanonical(LogValue.Sanitize(key, MaxLoggedValueLength), serialNumber);
                Counters.IncrementDecodeAnomaly(AndroidKeyAttestationStatusAnomalies.KeyNotCanonical, true);
            }

            entries.TryAdd(serialNumber, DecodeEntry(serialNumber, entryJson));
        }

        return Result<AndroidKeyAttestationStatusList>.Success(new(entries));
    }

    /// <summary>
    ///     Decodes an entry of the status list.
    /// </summary>
    /// <remarks>
    ///     An entry without a status, or with a status other than REVOKED and SUSPENDED, is kept: the certificate is in the status list, so it is untrusted. The anomaly is logged and counted.
    /// </remarks>
    /// <param name="serialNumber">The serial number of the certificate of the entry, normalized.</param>
    /// <param name="entryJson">The entry, or <see langword="null" /> if its value is <see langword="null" />.</param>
    /// <returns>The decoded entry.</returns>
    protected virtual AndroidKeyAttestationStatusEntry DecodeEntry(string serialNumber, AndroidKeyAttestationStatusEntryJSON? entryJson)
    {
        var status = entryJson?.Status;
        var reason = entryJson?.Reason;
        if (string.IsNullOrEmpty(status))
        {
            Logger.WarnEntryStatusMissing(serialNumber);
            Counters.IncrementDecodeAnomaly(AndroidKeyAttestationStatusAnomalies.StatusMissing, true);
            return new(null, reason);
        }

        if (status is not (StatusRevoked or StatusSuspended))
        {
            Logger.WarnEntryStatusUnknown(serialNumber, LogValue.Sanitize(status, MaxLoggedValueLength));
            Counters.IncrementDecodeAnomaly(AndroidKeyAttestationStatusAnomalies.StatusUnknown, true);
        }

        return new(status, reason);
    }

    /// <summary>
    ///     Normalizes the key of an entry: the serial number of a certificate in hexadecimal. The status list documents the keys in lowercase without leading zeros
    ///     (see <see cref="AndroidKeyAttestationStatusList.FormatSerialNumber" />), and a key in another case or with leading zeros still names the same certificate.
    /// </summary>
    /// <param name="key">The key of the entry.</param>
    /// <returns>The serial number in lowercase hexadecimal without leading zeros, or <see langword="null" /> if the key is not a serial number in hexadecimal.</returns>
    protected virtual string? NormalizeSerialNumber(string key)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length == 0 || !key.All(char.IsAsciiHexDigit))
        {
            return null;
        }

        var serialNumber = key.ToLowerInvariant().TrimStart('0');
        return serialNumber.Length > 0 ? serialNumber : "0";
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
}
