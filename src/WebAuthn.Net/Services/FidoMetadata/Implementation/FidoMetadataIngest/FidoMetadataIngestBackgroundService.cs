using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataIngest.Constants;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Providers;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataIngest;

/// <summary>
///     A service for background ingestion of metadata from the FIDO Metadata Service and their periodic update.
/// </summary>
/// <remarks>
///     <para>
///         The metadata is loaded at start-up, in <see cref="StartAsync" />: first the blob embedded in the application, if it is configured (<see cref="FidoMetadataIngestBackgroundServiceOptions.EmbeddedBlob" />),
///         and then the blob from the FIDO Metadata Service. If the embedded blob is loaded, the start of the application doesn't wait for the FIDO Metadata Service: the blob is downloaded in the background right away.
///         Otherwise, the start of the application waits for the first attempt to load the blob from the FIDO Metadata Service.
///     </para>
///     <para>
///         Then the metadata is updated in the background, in <see cref="ExecuteAsync" />, until the application stops. After a successful attempt, the next refresh takes place after
///         <see cref="FidoMetadataIngestBackgroundServiceOptions.IngestInterval" />, and after an unsuccessful one (the blob can't be downloaded, verified or decoded, or an exception occurred)
///         the next attempt takes place after <see cref="FidoMetadataIngestBackgroundServiceOptions.RetryInterval" />.
///     </para>
///     <para>
///         The start and the stop of the service are logged, and so are the result of every attempt, the delay before the next attempt and the time when it is made. A failed attempt
///         is also counted, and the attempts are repeated until the blob is loaded. Even an exception of an overridden method doesn't fail <see cref="ExecuteAsync" />:
///         it stops the background ingestion and is logged and counted too, so the host never treats the service as failed (which, by default, would stop the application,
///         see <see cref="HostOptions.BackgroundServiceExceptionBehavior" />).
///     </para>
/// </remarks>
public class FidoMetadataIngestBackgroundService : BackgroundService
{
    // The same as the defaults of FidoMetadataIngestBackgroundServiceOptions, used instead of an interval that is not positive.
    private static readonly TimeSpan DefaultIngestInterval = TimeSpan.FromDays(1);
    private static readonly TimeSpan DefaultRetryInterval = TimeSpan.FromMinutes(1);

    // Task.Delay doesn't support delays longer than about 49.7 days, so a longer delay is waited in parts.
    private static readonly TimeSpan MaxTaskDelay = TimeSpan.FromMilliseconds(uint.MaxValue - 1);

    // The number of failed downloads since the last successful one.
    private int _failedAttempts;

    // The delay before the first download in ExecuteAsync, set by StartAsync.
    private TimeSpan _initialDelay;

    /// <summary>
    ///     Constructs <see cref="FidoMetadataIngestBackgroundService" />.
    /// </summary>
    /// <param name="options">An accessor for obtaining the current value of options that set the parameters for the background ingest.</param>
    /// <param name="metadataIngestService">The ingestion service for metadata obtained from the FIDO Metadata Service, designed to store data from the retrieved blob.</param>
    /// <param name="fidoMetadataProvider">Provider of metadata from FIDO Metadata Service.</param>
    /// <param name="decoder">Decoder for data received from the FIDO Metadata Service's blob.</param>
    /// <param name="timeProvider">Current time provider, used to log the time when the next attempt to load the blob is made.</param>
    /// <param name="counters">Counters for FIDO Metadata Service metrics, used to count the attempts to load the blob that ended with an exception.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public FidoMetadataIngestBackgroundService(
        IOptionsMonitor<FidoMetadataIngestBackgroundServiceOptions> options,
        IFidoMetadataIngestService metadataIngestService,
        IFidoMetadataProvider fidoMetadataProvider,
        IFidoMetadataDecoder decoder,
        ITimeProvider timeProvider,
        IFidoMetadataCounters counters,
        ILogger<FidoMetadataIngestBackgroundService> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(metadataIngestService);
        ArgumentNullException.ThrowIfNull(fidoMetadataProvider);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(counters);
        ArgumentNullException.ThrowIfNull(logger);
        Options = options;
        MetadataIngestService = metadataIngestService;
        FidoMetadataProvider = fidoMetadataProvider;
        Decoder = decoder;
        TimeProvider = timeProvider;
        Counters = counters;
        Logger = logger;
    }

    /// <summary>
    ///     An accessor for obtaining the current value of options that set the parameters for the background ingest.
    /// </summary>
    protected IOptionsMonitor<FidoMetadataIngestBackgroundServiceOptions> Options { get; }

    /// <summary>
    ///     The ingestion service for metadata obtained from the FIDO Metadata Service, designed to store data from the retrieved blob.
    /// </summary>
    protected IFidoMetadataIngestService MetadataIngestService { get; }

    /// <summary>
    ///     Provider of metadata from FIDO Metadata Service.
    /// </summary>
    protected IFidoMetadataProvider FidoMetadataProvider { get; }

    /// <summary>
    ///     Decoder for data received from the FIDO Metadata Service's blob.
    /// </summary>
    protected IFidoMetadataDecoder Decoder { get; }

    /// <summary>
    ///     Current time provider, used to log the time when the next attempt to load the blob is made.
    /// </summary>
    protected ITimeProvider TimeProvider { get; }

    /// <summary>
    ///     Counters for FIDO Metadata Service metrics, used to count the attempts to load the blob that ended with an exception.
    /// </summary>
    protected IFidoMetadataCounters Counters { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<FidoMetadataIngestBackgroundService> Logger { get; }

    /// <inheritdoc />
    /// <remarks>
    ///     Loads the metadata before the background ingestion (<see cref="ExecuteAsync" />) is started: the blob embedded in the application, and, if it isn't loaded, the blob from the FIDO Metadata Service.
    ///     The start of the application waits for this method, so the metadata is available as soon as the application starts, unless neither blob could be loaded.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    ///     No metadata could be loaded at start-up: neither the blob embedded in the application nor the blob from the FIDO Metadata Service.
    ///     Only thrown if <see cref="FidoMetadataIngestBackgroundServiceOptions.ThrowExceptionOnFailure" /> is set.
    /// </exception>
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return;
        }

        Logger.InfoStarted();
        var options = Options.CurrentValue;
        if (options.EmbeddedBlob is not null && await LoadEmbeddedBlobAsync(options.EmbeddedBlob, cancellationToken))
        {
            // The metadata is available, so the start doesn't wait for the FIDO Metadata Service: the background ingestion downloads the blob right away.
            _initialDelay = TimeSpan.Zero;
        }
        else
        {
            // Without the embedded metadata, the start waits for the first attempt to load the blob from the FIDO Metadata Service.
            var downloaded = await DownloadBlobAsync(cancellationToken);
            if (!downloaded && options.ThrowExceptionOnFailure)
            {
                throw new InvalidOperationException("Failed to load metadata at start-up: neither the blob embedded in the application nor the blob from the FIDO Metadata Service could be loaded");
            }

            _initialDelay = GetNextDelay(downloaded);
        }

        await base.StartAsync(cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>
    ///     Stops the background ingestion (<see cref="ExecuteAsync" />) and logs that the ingestion has stopped.
    /// </remarks>
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken);
        Logger.InfoStopped();
    }

    /// <summary>
    ///     Asynchronously downloads and ingests metadata in an infinite loop, until the <paramref name="stoppingToken" /> triggers.
    ///     The first download takes place right away if the blob embedded in the application has been loaded at start-up, otherwise after the delay that follows the download at start-up.
    ///     The delay before each next download depends on the result of the previous one (see <see cref="GetNextDelay" />).
    /// </summary>
    /// <param name="stoppingToken">Triggered when the application stops.</param>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            var delay = _initialDelay;
            while (!stoppingToken.IsCancellationRequested)
            {
                await DelayAsync(delay, stoppingToken);
                var downloaded = await DownloadBlobAsync(stoppingToken);
                delay = GetNextDelay(downloaded);
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !stoppingToken.IsCancellationRequested)
        {
            // Every attempt handles its own failures, but an overridden method could still throw. A stopped background ingestion means that the metadata is not updated anymore,
            // so the exception is logged and counted here rather than passed to the host, which by default would stop the whole application.
            Logger.ErrorIngestBackgroundServiceStopped(exception);
            Counters.IncrementIngestException(FidoMetadataBlobSources.FidoMetadataService);
        }
    }

    /// <summary>
    ///     Asynchronously loads the blob embedded in the application, decodes and ingests it.
    /// </summary>
    /// <remarks>
    ///     A failure doesn't throw an exception (only the cancellation does): the reason is logged and counted, and the metadata is loaded from the FIDO Metadata Service only.
    /// </remarks>
    /// <param name="embeddedBlob">The blob embedded in the application (<see cref="FidoMetadataIngestBackgroundServiceOptions.EmbeddedBlob" />).</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>
    ///     <see langword="true" /> if the embedded blob was ingested, or the metadata in use is not older than it, so that the metadata is available.
    ///     <see langword="false" /> if the embedded blob could not be loaded, decoded or ingested.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="embeddedBlob" /> is <see langword="null" /></exception>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    protected virtual async Task<bool> LoadEmbeddedBlobAsync(FidoMetadataEmbeddedBlobOptions embeddedBlob, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(embeddedBlob);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var metadataResult = await FidoMetadataProvider.LoadEmbeddedMetadataAsync(embeddedBlob.Assembly, embeddedBlob.ResourceName, cancellationToken);
            if (metadataResult.HasError)
            {
                // The reason is logged and counted by the provider.
                Logger.WarnEmbeddedBlobNotLoaded();
                return false;
            }

            var decodeResult = Decoder.Decode(metadataResult.Ok);
            if (decodeResult.HasError)
            {
                Logger.WarnEmbeddedBlobDecodeFailed();
                return false;
            }

            await MetadataIngestService.UpsertEmbeddedAsync(decodeResult.Ok, cancellationToken);
            Logger.InfoEmbeddedBlobLoaded();
            return true;
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            // For example, a custom provider that doesn't support the embedded blob, or a timeout of a persistent storage.
            Logger.ErrorEmbeddedBlobLoadFailed(exception);
            Counters.IncrementIngestException(FidoMetadataBlobSources.Embedded);
            return false;
        }
    }

    /// <summary>
    ///     Asynchronously downloads the blob from the FIDO Metadata Service, decodes and ingests it.
    /// </summary>
    /// <remarks>
    ///     A failure doesn't throw an exception (only the cancellation does): the reason is logged and counted, so that it breaks neither the start of the application nor the background ingestion, which tries again later.
    /// </remarks>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>
    ///     <see langword="true" /> if the blob was ingested (or rejected by the ingestion service because the metadata in use is newer), so that the metadata is up to date.
    ///     <see langword="false" /> if the blob could not be downloaded, verified, decoded or ingested.
    /// </returns>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    protected virtual async Task<bool> DownloadBlobAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var metadataResult = await FidoMetadataProvider.DownloadMetadataAsync(cancellationToken);
            if (metadataResult.HasError)
            {
                Logger.FailedToDownload();
                return false;
            }

            var decodeResult = Decoder.Decode(metadataResult.Ok);
            if (decodeResult.HasError)
            {
                Logger.FailedToDecode();
                return false;
            }

            await MetadataIngestService.UpsertAsync(decodeResult.Ok, cancellationToken);
            return true;
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            // For example, an exception of a resilience policy of the HttpClient (a timeout or an open circuit breaker) or a timeout of a persistent storage.
            Logger.ErrorDownloadAndUpsertFailed(exception);
            Counters.IncrementIngestException(FidoMetadataBlobSources.FidoMetadataService);
            return false;
        }
    }

    /// <summary>
    ///     Returns the delay before the next download. Logs the success of the last download (the reason of a failure is logged by <see cref="DownloadBlobAsync" />),
    ///     the delay and the time when the next download is made.
    /// </summary>
    /// <param name="lastDownloadWasSuccessful">Whether the last download was successful.</param>
    /// <returns>
    ///     <see cref="FidoMetadataIngestBackgroundServiceOptions.IngestInterval" /> after a successful download, otherwise <see cref="FidoMetadataIngestBackgroundServiceOptions.RetryInterval" />.
    ///     An interval that is not positive is replaced by its default value.
    /// </returns>
    protected virtual TimeSpan GetNextDelay(bool lastDownloadWasSuccessful)
    {
        var options = Options.CurrentValue;
        if (lastDownloadWasSuccessful)
        {
            if (_failedAttempts > 0)
            {
                Logger.InfoLoadedAfterFailedAttempts(_failedAttempts);
                _failedAttempts = 0;
            }
            else
            {
                Logger.InfoLoaded();
            }

            var ingestInterval = GetIntervalOrDefault(options.IngestInterval, DefaultIngestInterval, nameof(options.IngestInterval));
            var nextRefreshTime = GetWakeUpTime(ingestInterval);
            Logger.InfoNextRefreshScheduled(ingestInterval, nextRefreshTime);
            return ingestInterval;
        }

        _failedAttempts++;
        var retryInterval = GetIntervalOrDefault(options.RetryInterval, DefaultRetryInterval, nameof(options.RetryInterval));
        var nextAttemptTime = GetWakeUpTime(retryInterval);
        Logger.InfoNextAttemptScheduled(retryInterval, nextAttemptTime, _failedAttempts);
        return retryInterval;
    }

    /// <summary>
    ///     Asynchronously waits before the next attempt to load the blob from the FIDO Metadata Service.
    /// </summary>
    /// <remarks>
    ///     A delay longer than <see cref="Task.Delay(TimeSpan, CancellationToken)" /> supports (about 49.7 days) is waited in parts.
    /// </remarks>
    /// <param name="delay">The delay.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    protected virtual async Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        var remaining = delay;
        while (remaining > TimeSpan.Zero)
        {
            var part = remaining < MaxTaskDelay ? remaining : MaxTaskDelay;
            await Task.Delay(part, cancellationToken);
            remaining -= part;
        }
    }

    private TimeSpan GetIntervalOrDefault(TimeSpan interval, TimeSpan defaultInterval, string optionName)
    {
        if (interval > TimeSpan.Zero)
        {
            return interval;
        }

        Logger.ErrorIntervalNotPositive(optionName, interval, defaultInterval);
        return defaultInterval;
    }

    // The time when a delay that starts now ends. A delay that would end after DateTimeOffset.MaxValue (for example, an interval of TimeSpan.MaxValue) ends at DateTimeOffset.MaxValue instead of throwing.
    private DateTimeOffset GetWakeUpTime(TimeSpan delay)
    {
        var now = TimeProvider.GetPreciseUtcDateTime();
        return delay < DateTimeOffset.MaxValue - now ? now + delay : DateTimeOffset.MaxValue;
    }
}

/// <summary>
///     Extension method for logging the background ingestion.
/// </summary>
public static partial class FidoMetadataIngestBackgroundServiceLoggingExtensions
{
    /// <summary>
    ///     The ingestion of metadata from the FIDO Metadata Service has started
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The ingestion of metadata from the FIDO Metadata Service has started")]
    public static partial void InfoStarted(this ILogger logger);

    /// <summary>
    ///     The ingestion of metadata from the FIDO Metadata Service has stopped
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The ingestion of metadata from the FIDO Metadata Service has stopped")]
    public static partial void InfoStopped(this ILogger logger);

    /// <summary>
    ///     Failed to download metadata from the FIDO Metadata Service.
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to download metadata from the FIDO Metadata Service")]
    public static partial void FailedToDownload(this ILogger logger);

    /// <summary>
    ///     Failed to decode data downloaded from the FIDO Metadata Service.
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode data downloaded from the FIDO Metadata Service")]
    public static partial void FailedToDecode(this ILogger logger);

    /// <summary>
    ///     Failed to load metadata from the FIDO Metadata Service because of an exception
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">The exception that interrupted the attempt.</param>
    [LoggerMessage(
        Level = LogLevel.Error,
        Message = "Failed to load metadata from the FIDO Metadata Service because of an exception")]
    public static partial void ErrorDownloadAndUpsertFailed(this ILogger logger, Exception exception);

    /// <summary>
    ///     The FIDO Metadata Service blob embedded in the application was loaded
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The FIDO Metadata Service blob embedded in the application was loaded")]
    public static partial void InfoEmbeddedBlobLoaded(this ILogger logger);

    /// <summary>
    ///     Failed to load the FIDO Metadata Service blob embedded in the application
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to load the FIDO Metadata Service blob embedded in the application")]
    public static partial void WarnEmbeddedBlobNotLoaded(this ILogger logger);

    /// <summary>
    ///     Failed to decode the FIDO Metadata Service blob embedded in the application
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the FIDO Metadata Service blob embedded in the application")]
    public static partial void WarnEmbeddedBlobDecodeFailed(this ILogger logger);

    /// <summary>
    ///     Failed to load the FIDO Metadata Service blob embedded in the application because of an exception
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">The exception that interrupted the loading.</param>
    [LoggerMessage(
        Level = LogLevel.Error,
        Message = "Failed to load the FIDO Metadata Service blob embedded in the application because of an exception")]
    public static partial void ErrorEmbeddedBlobLoadFailed(this ILogger logger, Exception exception);

    /// <summary>
    ///     The next attempt to load metadata from the FIDO Metadata Service will be made in {RetryInterval} (at {NextAttemptTime:O}), consecutive unsuccessful attempts: {FailedAttempts}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="retryInterval">The delay before the next attempt.</param>
    /// <param name="nextAttemptTime">The time when the next attempt is made.</param>
    /// <param name="failedAttempts">The number of consecutive unsuccessful attempts.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The next attempt to load metadata from the FIDO Metadata Service will be made in {RetryInterval} (at {NextAttemptTime:O}), consecutive unsuccessful attempts: {FailedAttempts}")]
    public static partial void InfoNextAttemptScheduled(this ILogger logger, TimeSpan retryInterval, DateTimeOffset nextAttemptTime, int failedAttempts);

    /// <summary>
    ///     Metadata was loaded from the FIDO Metadata Service
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "Metadata was loaded from the FIDO Metadata Service")]
    public static partial void InfoLoaded(this ILogger logger);

    /// <summary>
    ///     Metadata was loaded from the FIDO Metadata Service, consecutive unsuccessful attempts before it: {FailedAttempts}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="failedAttempts">The number of consecutive unsuccessful attempts before the successful one.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "Metadata was loaded from the FIDO Metadata Service, consecutive unsuccessful attempts before it: {FailedAttempts}")]
    public static partial void InfoLoadedAfterFailedAttempts(this ILogger logger, int failedAttempts);

    /// <summary>
    ///     The next refresh of metadata from the FIDO Metadata Service will be made in {IngestInterval} (at {NextRefreshTime:O})
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="ingestInterval">The delay before the next refresh.</param>
    /// <param name="nextRefreshTime">The time when the next refresh is made.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The next refresh of metadata from the FIDO Metadata Service will be made in {IngestInterval} (at {NextRefreshTime:O})")]
    public static partial void InfoNextRefreshScheduled(this ILogger logger, TimeSpan ingestInterval, DateTimeOffset nextRefreshTime);

    /// <summary>
    ///     The {Option} of {Value} is not a positive interval, so the default interval of {DefaultValue} is used instead
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="option">The name of the option.</param>
    /// <param name="value">The value of the option.</param>
    /// <param name="defaultValue">The default value of the option that is used instead.</param>
    [LoggerMessage(
        Level = LogLevel.Error,
        Message = "The {Option} of {Value} is not a positive interval, so the default interval of {DefaultValue} is used instead")]
    public static partial void ErrorIntervalNotPositive(this ILogger logger, string option, TimeSpan value, TimeSpan defaultValue);

    /// <summary>
    ///     The background ingestion of metadata from the FIDO Metadata Service has stopped because of an exception, so the metadata won't be updated until the application restarts
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">The exception that stopped the background ingestion.</param>
    [LoggerMessage(
        Level = LogLevel.Error,
        Message = "The background ingestion of metadata from the FIDO Metadata Service has stopped because of an exception, so the metadata won't be updated until the application restarts")]
    public static partial void ErrorIngestBackgroundServiceStopped(this ILogger logger, Exception exception);
}
