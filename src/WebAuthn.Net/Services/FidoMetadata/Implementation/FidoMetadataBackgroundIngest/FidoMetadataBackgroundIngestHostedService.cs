using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataBackgroundIngest.Constants;
using WebAuthn.Net.Services.Metrics;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataBackgroundIngest;

/// <summary>
///     A service for background ingestion of metadata from the FIDO Metadata Service and their periodic update.
/// </summary>
/// <remarks>
///     <para>
///         At start-up, the service loads the blob embedded in the application, if it is configured (<see cref="FidoMetadataBackgroundIngestHostedServiceOptions.EmbeddedBlobAssembly" />),
///         and then the blob from the FIDO Metadata Service. If the embedded blob is loaded, the start of the application doesn't wait for the FIDO Metadata Service: the blob is downloaded in the background right away.
///         Otherwise, the start of the application waits for the first attempt to load the blob from the FIDO Metadata Service.
///     </para>
///     <para>
///         After a successful attempt, the next refresh takes place after <see cref="FidoMetadataBackgroundIngestHostedServiceOptions.IngestInterval" />, and after an unsuccessful one
///         (the blob can't be downloaded, verified or decoded, or an exception occurred) the next attempt takes place after <see cref="FidoMetadataBackgroundIngestHostedServiceOptions.RetryInterval" />.
///         A failure never stops the background ingestion: it is logged and counted, and the attempts are repeated until the blob is loaded.
///     </para>
/// </remarks>
public class FidoMetadataBackgroundIngestHostedService : IHostedService, IDisposable
{
    // Task.Delay doesn't support delays longer than about 49.7 days, so a longer interval is waited in parts.
    private static readonly TimeSpan MaxDelayPart = TimeSpan.FromMilliseconds(uint.MaxValue - 1);

    private static readonly FidoMetadataBackgroundIngestHostedServiceOptions DefaultOptions = new();

    /// <summary>
    ///     Constructs <see cref="FidoMetadataBackgroundIngestHostedService" />.
    /// </summary>
    /// <param name="options">An accessor for obtaining the current value of options that set the parameters for the background ingest.</param>
    /// <param name="metadataIngestService">The ingestion service for metadata obtained from the FIDO Metadata Service, designed to store data from the retrieved blob.</param>
    /// <param name="provider">Provider of metadata from FIDO Metadata Service.</param>
    /// <param name="decoder">Decoder for data received from the FIDO Metadata Service's blob.</param>
    /// <param name="counters">Counters for FIDO Metadata Service metrics, used to count the attempts to load the blob that ended with an exception.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public FidoMetadataBackgroundIngestHostedService(
        IOptionsMonitor<FidoMetadataBackgroundIngestHostedServiceOptions> options,
        IFidoMetadataIngestService metadataIngestService,
        IFidoMetadataProvider provider,
        IFidoMetadataDecoder decoder,
        IFidoMetadataCounters counters,
        ILogger<FidoMetadataBackgroundIngestHostedService> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(metadataIngestService);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(counters);
        ArgumentNullException.ThrowIfNull(logger);
        Options = options;
        MetadataIngestService = metadataIngestService;
        Provider = provider;
        Decoder = decoder;
        Counters = counters;
        Logger = logger;
    }

    /// <summary>
    ///     A background task that performs periodic updating of FIDO metadata.
    /// </summary>
    protected Task? PeriodicBackgroundUpdateTask { get; set; }

    /// <summary>
    ///     Cancellation token for the execution of a background task.
    /// </summary>
    protected CancellationTokenSource? StoppingCts { get; set; }

    /// <summary>
    ///     An accessor for obtaining the current value of options that set the parameters for the background ingest.
    /// </summary>
    protected IOptionsMonitor<FidoMetadataBackgroundIngestHostedServiceOptions> Options { get; }

    /// <summary>
    ///     The ingestion service for metadata obtained from the FIDO Metadata Service, designed to store data from the retrieved blob.
    /// </summary>
    protected IFidoMetadataIngestService MetadataIngestService { get; }

    /// <summary>
    ///     Provider of metadata from FIDO Metadata Service.
    /// </summary>
    protected IFidoMetadataProvider Provider { get; }

    /// <summary>
    ///     Decoder for data received from the FIDO Metadata Service's blob.
    /// </summary>
    protected IFidoMetadataDecoder Decoder { get; }

    /// <summary>
    ///     Counters for FIDO Metadata Service metrics, used to count the attempts to load the blob that ended with an exception.
    /// </summary>
    protected IFidoMetadataCounters Counters { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<FidoMetadataBackgroundIngestHostedService> Logger { get; }

    /// <summary>
    ///     The number of consecutive unsuccessful attempts to load the blob from the FIDO Metadata Service. A successful attempt resets it to zero.
    /// </summary>
    protected int ConsecutiveFailedAttempts { get; set; }

    /// <inheritdoc />
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <inheritdoc />
    /// <exception cref="InvalidOperationException">
    ///     No metadata could be loaded at start-up: neither the blob embedded in the application nor the blob from the FIDO Metadata Service.
    ///     Only thrown if <see cref="FidoMetadataBackgroundIngestHostedServiceOptions.ThrowExceptionOnFailure" /> is set.
    /// </exception>
    public virtual async Task StartAsync(CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return;
        }

        // The blob embedded in the application (if any) is loaded first: it makes the metadata available right away, regardless of the availability of the FIDO Metadata Service.
        if (await IngestEmbeddedMetadataAsync(cancellationToken))
        {
            // The metadata is available, so the start doesn't wait for the FIDO Metadata Service: the blob is downloaded in the background right away.
            await StartBackgroundIngestAsync(TimeSpan.Zero, cancellationToken);
            return;
        }

        // Without the embedded metadata, the start waits for the first attempt to load the blob from the FIDO Metadata Service.
        var loaded = await DownloadAndUpsertMetadataAsync(cancellationToken);
        if (!loaded && Options.CurrentValue.ThrowExceptionOnFailure)
        {
            throw new InvalidOperationException("Failed to load metadata at start-up: neither the blob embedded in the application nor the blob from the FIDO Metadata Service could be loaded");
        }

        await StartBackgroundIngestAsync(ScheduleNextAttempt(loaded), cancellationToken);
    }

    /// <inheritdoc />
    public virtual async Task StopAsync(CancellationToken cancellationToken)
    {
        // Stop called without a start
        if (PeriodicBackgroundUpdateTask == null)
        {
            return;
        }

        try
        {
            // Signal cancellation to the executing method
            var stoppingCts = StoppingCts;
            if (stoppingCts is not null)
            {
                await stoppingCts.CancelAsync();
            }
        }
        finally
        {
            // Wait until the task completes or the stop token triggers
            await Task.WhenAny(PeriodicBackgroundUpdateTask, Task.Delay(Timeout.Infinite, cancellationToken)).ConfigureAwait(false);
        }
    }

    /// <summary>
    ///     Starts an asynchronous task that performs metadata update in the background.
    /// </summary>
    /// <param name="delay">The delay before the first attempt to load the blob from the FIDO Metadata Service.</param>
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>An asynchronous task that performs metadata update in the background.</returns>
    protected virtual Task StartBackgroundIngestAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        // Create a linked token to allow cancelling an executing task from the provided token
        StoppingCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        // Store the task we're executing
        PeriodicBackgroundUpdateTask = RunBackgroundIngestAsync(delay, StoppingCts.Token);

        // If the task is completed, then return it. This will bubble cancellation and failure to the caller
        if (PeriodicBackgroundUpdateTask.IsCompleted)
        {
            return PeriodicBackgroundUpdateTask;
        }

        // Otherwise it's running
        return Task.CompletedTask;
    }

    /// <summary>
    ///     Asynchronously downloads and ingests metadata in an infinite loop, until the <paramref name="stoppingToken" /> triggers.
    ///     The delay before each next attempt depends on the result of the previous one (see <see cref="ScheduleNextAttempt" />).
    /// </summary>
    /// <param name="delay">The delay before the first attempt.</param>
    /// <param name="stoppingToken">Cancellation token for an asynchronous operation.</param>
    protected virtual async Task BackgroundIngestAsync(TimeSpan delay, CancellationToken stoppingToken)
    {
        var nextDelay = delay;
        while (!stoppingToken.IsCancellationRequested)
        {
            await DelayAsync(nextDelay, stoppingToken);
            var loaded = await DownloadAndUpsertMetadataAsync(stoppingToken);
            nextDelay = ScheduleNextAttempt(loaded);
        }
    }

    /// <summary>
    ///     Asynchronously loads the blob embedded in the application (<see cref="FidoMetadataBackgroundIngestHostedServiceOptions.EmbeddedBlobAssembly" />
    ///     and <see cref="FidoMetadataBackgroundIngestHostedServiceOptions.EmbeddedBlobResourceName" />), decodes and ingests it.
    /// </summary>
    /// <remarks>
    ///     A failure doesn't throw an exception (only the cancellation does): the reason is logged and counted, and the metadata is loaded from the FIDO Metadata Service only.
    /// </remarks>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>
    ///     <see langword="true" /> if the embedded blob was ingested, or the metadata in use is not older than it, so that the metadata is available.
    ///     <see langword="false" /> if no blob is embedded in the application, or it could not be loaded, decoded or ingested.
    /// </returns>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    protected virtual async Task<bool> IngestEmbeddedMetadataAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var options = Options.CurrentValue;
        var assembly = options.EmbeddedBlobAssembly;
        var resourceName = options.EmbeddedBlobResourceName;
        if (assembly is null && string.IsNullOrEmpty(resourceName))
        {
            return false;
        }

        if (assembly is null || string.IsNullOrEmpty(resourceName))
        {
            Logger.WarnEmbeddedBlobNotConfiguredCompletely();
            return false;
        }

        try
        {
            var metadataResult = await Provider.LoadEmbeddedMetadataAsync(assembly, resourceName, cancellationToken);
            if (metadataResult.HasError)
            {
                // The reason is logged and counted by the provider.
                return false;
            }

            var decodeResult = Decoder.Decode(metadataResult.Ok);
            if (decodeResult.HasError)
            {
                Logger.WarnEmbeddedBlobDecodeFailed();
                return false;
            }

            await MetadataIngestService.UpsertEmbeddedAsync(decodeResult.Ok, cancellationToken);
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
    ///     Asynchronously downloads and ingests metadata from the FIDO Metadata Service
    /// </summary>
    /// <remarks>
    ///     A failure doesn't throw an exception (only the cancellation does): the reason is logged and counted, so that it breaks neither the start of the application nor the background ingestion, which tries again later.
    /// </remarks>
    /// <param name="stoppingToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>
    ///     <see langword="true" /> if the blob was ingested (or rejected by the ingestion service because the metadata in use is newer), so that the metadata is up to date.
    ///     <see langword="false" /> if the blob could not be downloaded, verified, decoded or ingested.
    /// </returns>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    protected virtual async Task<bool> DownloadAndUpsertMetadataAsync(CancellationToken stoppingToken)
    {
        stoppingToken.ThrowIfCancellationRequested();
        try
        {
            var metadataResult = await Provider.DownloadMetadataAsync(stoppingToken);
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

            await MetadataIngestService.UpsertAsync(decodeResult.Ok, stoppingToken);
            return true;
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !stoppingToken.IsCancellationRequested)
        {
            // For example, an exception of a resilience policy of the HttpClient (a timeout or an open circuit breaker) or a timeout of a persistent storage.
            Logger.ErrorDownloadAndUpsertFailed(exception);
            Counters.IncrementIngestException(FidoMetadataBlobSources.FidoMetadataService);
            return false;
        }
    }

    /// <summary>
    ///     Returns the delay before the next attempt to load the blob from the FIDO Metadata Service and logs it.
    /// </summary>
    /// <param name="lastAttemptSucceeded">Flag indicating whether the last attempt to load the blob from the FIDO Metadata Service was successful.</param>
    /// <returns>
    ///     <see cref="FidoMetadataBackgroundIngestHostedServiceOptions.IngestInterval" /> after a successful attempt, otherwise <see cref="FidoMetadataBackgroundIngestHostedServiceOptions.RetryInterval" />.
    ///     An interval that is not positive is replaced by its default value.
    /// </returns>
    protected virtual TimeSpan ScheduleNextAttempt(bool lastAttemptSucceeded)
    {
        var options = Options.CurrentValue;
        if (lastAttemptSucceeded)
        {
            if (ConsecutiveFailedAttempts > 0)
            {
                Logger.InfoLoadedAfterFailedAttempts(ConsecutiveFailedAttempts);
                ConsecutiveFailedAttempts = 0;
            }

            var ingestInterval = GetPositiveInterval(options.IngestInterval, DefaultOptions.IngestInterval, nameof(FidoMetadataBackgroundIngestHostedServiceOptions.IngestInterval));
            Logger.DebugNextRefreshScheduled(ingestInterval);
            return ingestInterval;
        }

        ConsecutiveFailedAttempts++;
        var retryInterval = GetPositiveInterval(options.RetryInterval, DefaultOptions.RetryInterval, nameof(FidoMetadataBackgroundIngestHostedServiceOptions.RetryInterval));
        Logger.InfoNextAttemptScheduled(retryInterval, ConsecutiveFailedAttempts);
        return retryInterval;
    }

    /// <summary>
    ///     Asynchronously waits before the next attempt to load the blob from the FIDO Metadata Service.
    /// </summary>
    /// <remarks>
    ///     The default implementation always completes asynchronously, even for a zero delay, so that the attempt that follows never runs synchronously within the start of the application.
    ///     A delay longer than <see cref="Task.Delay(TimeSpan, CancellationToken)" /> supports (about 49.7 days) is waited in parts.
    /// </remarks>
    /// <param name="delay">The delay.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    protected virtual async Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        if (delay <= TimeSpan.Zero)
        {
            await Task.Yield();
            cancellationToken.ThrowIfCancellationRequested();
            return;
        }

        var remaining = delay;
        while (remaining > TimeSpan.Zero)
        {
            var part = remaining < MaxDelayPart ? remaining : MaxDelayPart;
            await Task.Delay(part, cancellationToken);
            remaining -= part;
        }
    }

    /// <summary>
    ///     Releases all resources currently used by this <see cref="FidoMetadataBackgroundIngestHostedService" /> instance.
    /// </summary>
    /// <param name="disposing"><see langword="true" /> if this method is being invoked by the <see cref="Dispose()" /> method, otherwise <see langword="false" />.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            // The host disposes the hosted services without stopping them when it fails to start (for example, when the port is already in use).
            // In this case the periodic background task is still running, and a Task can be disposed only when it is completed,
            // so the task is cancelled first and disposed only if it has already completed.
            var stoppingCts = StoppingCts;
            if (stoppingCts is not null && !stoppingCts.IsCancellationRequested)
            {
                stoppingCts.Cancel();
            }

            var periodicBackgroundUpdateTask = PeriodicBackgroundUpdateTask;
            if (periodicBackgroundUpdateTask is { IsCompleted: true })
            {
                periodicBackgroundUpdateTask.Dispose();
            }

            stoppingCts?.Dispose();
        }
    }

    // The background ingestion itself never ends with an exception other than the cancellation, but an overridden one could:
    // a stopped background ingestion means that the metadata is not updated anymore, so it must not stop silently.
    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    private async Task RunBackgroundIngestAsync(TimeSpan delay, CancellationToken stoppingToken)
    {
        try
        {
            await BackgroundIngestAsync(delay, stoppingToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !stoppingToken.IsCancellationRequested)
        {
            Logger.ErrorBackgroundIngestStopped(exception);
            Counters.IncrementIngestException(FidoMetadataBlobSources.FidoMetadataService);
        }
    }

    private TimeSpan GetPositiveInterval(TimeSpan interval, TimeSpan defaultInterval, string optionName)
    {
        if (interval > TimeSpan.Zero)
        {
            return interval;
        }

        Logger.ErrorIntervalNotPositive(optionName, interval, defaultInterval);
        return defaultInterval;
    }
}

/// <summary>
///     Extension method for logging the background ingestion.
/// </summary>
public static partial class FidoMetadataBackgroundIngestHostedServiceLoggingExtensions
{
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
    ///     The FIDO Metadata Service blob embedded in the application is not loaded: both EmbeddedBlobAssembly and EmbeddedBlobResourceName have to be set
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The FIDO Metadata Service blob embedded in the application is not loaded: both EmbeddedBlobAssembly and EmbeddedBlobResourceName have to be set")]
    public static partial void WarnEmbeddedBlobNotConfiguredCompletely(this ILogger logger);

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
    ///     The next attempt to load metadata from the FIDO Metadata Service will be made in {RetryInterval}, consecutive unsuccessful attempts: {FailedAttempts}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="retryInterval">The delay before the next attempt.</param>
    /// <param name="failedAttempts">The number of consecutive unsuccessful attempts.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The next attempt to load metadata from the FIDO Metadata Service will be made in {RetryInterval}, consecutive unsuccessful attempts: {FailedAttempts}")]
    public static partial void InfoNextAttemptScheduled(this ILogger logger, TimeSpan retryInterval, int failedAttempts);

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
    ///     The next refresh of metadata from the FIDO Metadata Service will be made in {IngestInterval}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="ingestInterval">The delay before the next refresh.</param>
    [LoggerMessage(
        Level = LogLevel.Debug,
        Message = "The next refresh of metadata from the FIDO Metadata Service will be made in {IngestInterval}")]
    public static partial void DebugNextRefreshScheduled(this ILogger logger, TimeSpan ingestInterval);

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
    public static partial void ErrorBackgroundIngestStopped(this ILogger logger, Exception exception);
}
