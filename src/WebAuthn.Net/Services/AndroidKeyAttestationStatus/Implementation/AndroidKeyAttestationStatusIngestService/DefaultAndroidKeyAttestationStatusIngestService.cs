using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models;
using WebAuthn.Net.Storage.AndroidKeyAttestationStatus;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusIngestService;

/// <summary>
///     Default implementation of <see cref="IAndroidKeyAttestationStatusIngestService" />.
/// </summary>
/// <remarks>
///     The downloaded status list always replaces the status list in use: it has no serial number, and Google publishes only the current one.
///     The status list embedded in the application (<see cref="UpsertEmbeddedAsync" />) is upserted only if no status list is in use yet: it is a fallback for the start without the download,
///     while a status list that a persistent storage keeps was downloaded later than the application was built.
/// </remarks>
public class DefaultAndroidKeyAttestationStatusIngestService : IAndroidKeyAttestationStatusIngestService
{
    /// <summary>
    ///     Constructs <see cref="DefaultAndroidKeyAttestationStatusIngestService" />.
    /// </summary>
    /// <param name="storage">Storage of the status list that is in use.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultAndroidKeyAttestationStatusIngestService(
        IAndroidKeyAttestationStatusStorage storage,
        ILogger<DefaultAndroidKeyAttestationStatusIngestService> logger)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(logger);
        Storage = storage;
        Logger = logger;
    }

    /// <summary>
    ///     Storage of the status list that is in use.
    /// </summary>
    protected IAndroidKeyAttestationStatusStorage Storage { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultAndroidKeyAttestationStatusIngestService> Logger { get; }

    /// <inheritdoc />
    public virtual async Task UpsertAsync(
        AndroidKeyAttestationStatusList statusList,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(statusList);
        cancellationToken.ThrowIfCancellationRequested();
        await Storage.UpsertAsync(statusList, cancellationToken);
        Logger.InfoStatusListIngested(statusList.Entries.Count);
    }

    /// <inheritdoc />
    /// <remarks>
    ///     The embedded status list is upserted only if there is no status list in use yet. Otherwise the status list in use is kept, and this is logged at the <see cref="LogLevel.Information" /> level.
    /// </remarks>
    public virtual async Task UpsertEmbeddedAsync(
        AndroidKeyAttestationStatusList statusList,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(statusList);
        cancellationToken.ThrowIfCancellationRequested();
        if (await Storage.GetAsync(cancellationToken) is not null)
        {
            Logger.InfoEmbeddedStatusListNotUsed();
            return;
        }

        await Storage.UpsertAsync(statusList, cancellationToken);
        Logger.InfoEmbeddedStatusListIngested(statusList.Entries.Count);
    }
}

/// <summary>
///     Extension methods for logging the ingestion of the certificate revocation status list of the Android attestation keys.
/// </summary>
public static partial class DefaultAndroidKeyAttestationStatusIngestServiceLoggingExtensions
{
    /// <summary>
    ///     The status list of the Android attestation keys with {Entries} entries was ingested
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="entries">The number of entries in the ingested status list.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The status list of the Android attestation keys with {Entries} entries was ingested")]
    public static partial void InfoStatusListIngested(this ILogger logger, int entries);

    /// <summary>
    ///     The status list of the Android attestation keys with {Entries} entries embedded in the application was ingested
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="entries">The number of entries in the ingested status list.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The status list of the Android attestation keys with {Entries} entries embedded in the application was ingested")]
    public static partial void InfoEmbeddedStatusListIngested(this ILogger logger, int entries);

    /// <summary>
    ///     The status list of the Android attestation keys embedded in the application was not ingested because a status list is already in use
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The status list of the Android attestation keys embedded in the application was not ingested because a status list is already in use")]
    public static partial void InfoEmbeddedStatusListNotUsed(this ILogger logger);
}
