using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Configuration.Options.AttestationStatements;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusIngest.Constants;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Storage.AndroidKeyAttestationStatus;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusIngest;

/// <summary>
///     A service for background ingestion of the <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a>
///     of the Android attestation keys and its periodic update.
/// </summary>
/// <remarks>
///     <para>
///         The status list is loaded at start-up, in <see cref="StartAsync" />: first the status list embedded in the application, if it is configured (<see cref="AndroidKeyAttestationStatusListOptions.EmbeddedStatusList" />),
///         and then the status list downloaded from <see cref="AndroidKeyAttestationStatusListOptions.DownloadUri" />. If the embedded status list is loaded, the start of the application doesn't wait for the download:
///         the status list is downloaded in the background right away. Otherwise, the start of the application waits for the first attempt to download it.
///     </para>
///     <para>
///         Then the status list is updated in the background, in <see cref="ExecuteAsync" />, until the application stops. After a successful attempt, the next refresh takes place after
///         <see cref="AndroidKeyAttestationStatusListOptions.IngestInterval" />, and after an unsuccessful one (the status list can't be downloaded or decoded, or an exception occurred)
///         the next attempt takes place after <see cref="AndroidKeyAttestationStatusListOptions.RetryInterval" />.
///     </para>
///     <para>
///         The start and the stop of the service are logged, and so are the result of every attempt, the delay before the next attempt and the time when it is made. A failed attempt
///         is also counted, and the attempts are repeated until the status list is downloaded. Even an exception of an overridden method doesn't fail <see cref="ExecuteAsync" />:
///         it stops the background ingestion and is logged and counted too, so the host never treats the service as failed (which, by default, would stop the application,
///         see <see cref="HostOptions.BackgroundServiceExceptionBehavior" />).
///     </para>
/// </remarks>
public class AndroidKeyAttestationStatusIngestBackgroundService : BackgroundService
{
    // The same as the defaults of AndroidKeyAttestationStatusListOptions, used instead of an interval that is not positive.
    private static readonly TimeSpan DefaultIngestInterval = TimeSpan.FromDays(1);
    private static readonly TimeSpan DefaultRetryInterval = TimeSpan.FromMinutes(1);

    // Task.Delay doesn't support delays longer than about 49.7 days, so a longer delay is waited in parts.
    private static readonly TimeSpan MaxTaskDelay = TimeSpan.FromMilliseconds(uint.MaxValue - 1);

    // The number of failed downloads since the last successful one.
    private int _failedAttempts;

    // The delay before the first download in ExecuteAsync, set by StartAsync.
    private TimeSpan _initialDelay;

    /// <summary>
    ///     Constructs <see cref="AndroidKeyAttestationStatusIngestBackgroundService" />.
    /// </summary>
    /// <param name="options">Accessor for getting the current value of global options, which contain the options of the status list.</param>
    /// <param name="httpClient">An HTTP client for downloading the status list.</param>
    /// <param name="decoder">Decoder of the status list.</param>
    /// <param name="storage">Storage of the status list that is in use.</param>
    /// <param name="timeProvider">Current time provider, used to log the time when the next attempt to download the status list is made.</param>
    /// <param name="counters">Counters for the metrics of the status list, used to count the failed attempts to load it.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public AndroidKeyAttestationStatusIngestBackgroundService(
        IOptionsMonitor<WebAuthnOptions> options,
        IAndroidKeyAttestationStatusHttpClient httpClient,
        IAndroidKeyAttestationStatusDecoder decoder,
        IAndroidKeyAttestationStatusStorage storage,
        ITimeProvider timeProvider,
        IAndroidKeyAttestationStatusCounters counters,
        ILogger<AndroidKeyAttestationStatusIngestBackgroundService> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(counters);
        ArgumentNullException.ThrowIfNull(logger);
        Options = options;
        HttpClient = httpClient;
        Decoder = decoder;
        Storage = storage;
        TimeProvider = timeProvider;
        Counters = counters;
        Logger = logger;
    }

    /// <summary>
    ///     Accessor for getting the current value of global options, which contain the options of the status list.
    /// </summary>
    protected IOptionsMonitor<WebAuthnOptions> Options { get; }

    /// <summary>
    ///     An HTTP client for downloading the status list.
    /// </summary>
    protected IAndroidKeyAttestationStatusHttpClient HttpClient { get; }

    /// <summary>
    ///     Decoder of the status list.
    /// </summary>
    protected IAndroidKeyAttestationStatusDecoder Decoder { get; }

    /// <summary>
    ///     Storage of the status list that is in use.
    /// </summary>
    protected IAndroidKeyAttestationStatusStorage Storage { get; }

    /// <summary>
    ///     Current time provider, used to log the time when the next attempt to download the status list is made.
    /// </summary>
    protected ITimeProvider TimeProvider { get; }

    /// <summary>
    ///     Counters for the metrics of the status list, used to count the failed attempts to load it.
    /// </summary>
    protected IAndroidKeyAttestationStatusCounters Counters { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<AndroidKeyAttestationStatusIngestBackgroundService> Logger { get; }

    /// <inheritdoc />
    /// <remarks>
    ///     Loads the status list before the background ingestion (<see cref="ExecuteAsync" />) is started: the status list embedded in the application, and, if it isn't loaded, the downloaded one.
    ///     The start of the application waits for this method, so the status list is available as soon as the application starts, unless neither could be loaded.
    /// </remarks>
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return;
        }

        Logger.InfoStarted();
        var embeddedStatusList = Options.CurrentValue.AttestationStatements.AndroidKey.StatusList.EmbeddedStatusList;
        if (embeddedStatusList is not null && await LoadEmbeddedStatusListAsync(embeddedStatusList, cancellationToken))
        {
            // The status list is available, so the start doesn't wait for the download: the background ingestion downloads the status list right away.
            _initialDelay = TimeSpan.Zero;
        }
        else
        {
            // Without the embedded status list, the start waits for the first attempt to download the status list.
            var downloaded = await DownloadStatusListAsync(cancellationToken);
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
    ///     Asynchronously downloads and stores the status list in an infinite loop, until the <paramref name="stoppingToken" /> triggers.
    ///     The first download takes place right away if the status list embedded in the application has been loaded at start-up, otherwise after the delay that follows the download at start-up.
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
                var downloaded = await DownloadStatusListAsync(stoppingToken);
                delay = GetNextDelay(downloaded);
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !stoppingToken.IsCancellationRequested)
        {
            // Every attempt handles its own failures, but an overridden method could still throw. A stopped background ingestion means that the status list is not updated anymore,
            // so the exception is logged and counted here rather than passed to the host, which by default would stop the whole application.
            Logger.ErrorIngestBackgroundServiceStopped(exception);
            Counters.IncrementIngestException(AndroidKeyAttestationStatusListSources.Download);
        }
    }

    /// <summary>
    ///     Asynchronously loads the status list embedded in the application, decodes and stores it.
    /// </summary>
    /// <remarks>
    ///     A failure doesn't throw an exception (only the cancellation does): the reason is logged and counted, and the status list is downloaded only.
    /// </remarks>
    /// <param name="embeddedStatusList">The status list embedded in the application (<see cref="AndroidKeyAttestationStatusListOptions.EmbeddedStatusList" />).</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns><see langword="true" /> if the embedded status list was stored, so that the status list is available, otherwise <see langword="false" />.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="embeddedStatusList" /> is <see langword="null" /></exception>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    protected virtual async Task<bool> LoadEmbeddedStatusListAsync(AndroidKeyAttestationEmbeddedStatusListOptions embeddedStatusList, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(embeddedStatusList);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var assembly = embeddedStatusList.Assembly;
            var resourceName = embeddedStatusList.ResourceName;
            string json;
            await using (var resourceStream = assembly.GetManifestResourceStream(resourceName))
            {
                if (resourceStream is null)
                {
                    Logger.WarnEmbeddedStatusListResourceNotFound(resourceName, assembly.FullName, FormatManifestResourceNames(assembly));
                    Counters.IncrementEmbeddedFailure(AndroidKeyAttestationStatusListFailures.ResourceNotFound);
                    return false;
                }

                using var reader = new StreamReader(resourceStream, Encoding.UTF8, true);
                json = await reader.ReadToEndAsync(cancellationToken);
            }

            var decodeResult = Decoder.Decode(json);
            if (decodeResult.HasError)
            {
                Logger.WarnEmbeddedStatusListInvalid(resourceName, assembly.FullName);
                Counters.IncrementEmbeddedFailure(AndroidKeyAttestationStatusListFailures.ListInvalid);
                return false;
            }

            await Storage.UpsertAsync(decodeResult.Ok, cancellationToken);
            Logger.InfoEmbeddedStatusListLoaded(decodeResult.Ok.Entries.Count);
            return true;
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            // For example, a timeout of a persistent storage.
            Logger.ErrorEmbeddedStatusListLoadFailed(exception);
            Counters.IncrementIngestException(AndroidKeyAttestationStatusListSources.Embedded);
            return false;
        }
    }

    /// <summary>
    ///     Asynchronously downloads the status list, decodes and stores it.
    /// </summary>
    /// <remarks>
    ///     A failure doesn't throw an exception (only the cancellation does): the reason is logged and counted, so that it breaks neither the start of the application nor the background ingestion, which tries again later.
    /// </remarks>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns><see langword="true" /> if the status list was downloaded and stored, otherwise <see langword="false" />.</returns>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    protected virtual async Task<bool> DownloadStatusListAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            string json;
            try
            {
                json = await HttpClient.DownloadStatusListAsync(cancellationToken);
            }
            catch (Exception exception) when (exception is HttpRequestException or TimeoutException or IOException)
            {
                // The request failed, the response has an unsuccessful status code or exceeds the limits of the client, or the connection was broken.
                // A failed download is an expected failure rather than an exception: it is logged and counted with its reason, and the download is retried later.
                Logger.WarnDownloadFailed(exception);
                Counters.IncrementDownloadFailure(exception is TimeoutException
                    ? AndroidKeyAttestationStatusListFailures.Timeout
                    : AndroidKeyAttestationStatusListFailures.RequestFailed);
                return false;
            }

            var decodeResult = Decoder.Decode(json);
            if (decodeResult.HasError)
            {
                Logger.WarnDownloadedStatusListInvalid();
                Counters.IncrementDownloadFailure(AndroidKeyAttestationStatusListFailures.ListInvalid);
                return false;
            }

            await Storage.UpsertAsync(decodeResult.Ok, cancellationToken);
            Logger.InfoDownloaded(decodeResult.Ok.Entries.Count);
            return true;
        }
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            // For example, an exception of a resilience policy of the HttpClient (an open circuit breaker) or a timeout of a persistent storage.
            Logger.ErrorDownloadAndUpsertFailed(exception);
            Counters.IncrementIngestException(AndroidKeyAttestationStatusListSources.Download);
            return false;
        }
    }

    /// <summary>
    ///     Returns the delay before the next download. Logs the number of unsuccessful attempts before a successful one (the success and the reason of a failure are logged by <see cref="DownloadStatusListAsync" />),
    ///     the delay and the time when the next download is made.
    /// </summary>
    /// <param name="lastDownloadWasSuccessful">Whether the last download was successful.</param>
    /// <returns>
    ///     <see cref="AndroidKeyAttestationStatusListOptions.IngestInterval" /> after a successful download, otherwise <see cref="AndroidKeyAttestationStatusListOptions.RetryInterval" />.
    ///     An interval that is not positive is replaced by its default value.
    /// </returns>
    protected virtual TimeSpan GetNextDelay(bool lastDownloadWasSuccessful)
    {
        var options = Options.CurrentValue.AttestationStatements.AndroidKey.StatusList;
        if (lastDownloadWasSuccessful)
        {
            if (_failedAttempts > 0)
            {
                Logger.InfoDownloadedAfterFailedAttempts(_failedAttempts);
                _failedAttempts = 0;
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
    ///     Asynchronously waits before the next attempt to download the status list.
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

    private static string FormatManifestResourceNames(Assembly assembly)
    {
        const int maxNames = 16;
        var names = assembly.GetManifestResourceNames();
        if (names.Length == 0)
        {
            return "<none>";
        }

        var formattedNames = string.Join(", ", names.Order(StringComparer.Ordinal).Take(maxNames).Select(static x => $"'{x}'"));
        return names.Length > maxNames
            ? $"{formattedNames}, ... ({names.Length} in total)"
            : formattedNames;
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
///     Extension methods for logging the background ingestion of the certificate revocation status list of the Android attestation keys.
/// </summary>
public static partial class AndroidKeyAttestationStatusIngestBackgroundServiceLoggingExtensions
{
    /// <summary>
    ///     The ingestion of the status list of the Android attestation keys has started
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The ingestion of the status list of the Android attestation keys has started")]
    public static partial void InfoStarted(this ILogger logger);

    /// <summary>
    ///     The ingestion of the status list of the Android attestation keys has stopped
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The ingestion of the status list of the Android attestation keys has stopped")]
    public static partial void InfoStopped(this ILogger logger);

    /// <summary>
    ///     The status list of the Android attestation keys embedded in the application was loaded: {EntryCount} entries
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="entryCount">The number of entries of the status list.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The status list of the Android attestation keys embedded in the application was loaded: {EntryCount} entries")]
    public static partial void InfoEmbeddedStatusListLoaded(this ILogger logger, int entryCount);

    /// <summary>
    ///     The status list of the Android attestation keys embedded in the application can't be loaded: the assembly '{Assembly}' doesn't contain the manifest resource '{ResourceName}' (the manifest resources of the assembly: {ResourceNames})
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="resourceName">The name of the manifest resource of the status list.</param>
    /// <param name="assembly">The full name of the assembly.</param>
    /// <param name="resourceNames">The names of the manifest resources of the assembly.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The status list of the Android attestation keys embedded in the application can't be loaded: the assembly '{Assembly}' doesn't contain the manifest resource '{ResourceName}' (the manifest resources of the assembly: {ResourceNames})")]
    public static partial void WarnEmbeddedStatusListResourceNotFound(this ILogger logger, string resourceName, string? assembly, string resourceNames);

    /// <summary>
    ///     The status list of the Android attestation keys embedded in the application (the manifest resource '{ResourceName}' of the assembly '{Assembly}') is malformed
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="resourceName">The name of the manifest resource of the status list.</param>
    /// <param name="assembly">The full name of the assembly.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The status list of the Android attestation keys embedded in the application (the manifest resource '{ResourceName}' of the assembly '{Assembly}') is malformed")]
    public static partial void WarnEmbeddedStatusListInvalid(this ILogger logger, string resourceName, string? assembly);

    /// <summary>
    ///     Failed to load the status list of the Android attestation keys embedded in the application because of an exception
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">The exception that interrupted the loading.</param>
    [LoggerMessage(
        Level = LogLevel.Error,
        Message = "Failed to load the status list of the Android attestation keys embedded in the application because of an exception")]
    public static partial void ErrorEmbeddedStatusListLoadFailed(this ILogger logger, Exception exception);

    /// <summary>
    ///     The status list of the Android attestation keys was downloaded: {EntryCount} entries
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="entryCount">The number of entries of the status list.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The status list of the Android attestation keys was downloaded: {EntryCount} entries")]
    public static partial void InfoDownloaded(this ILogger logger, int entryCount);

    /// <summary>
    ///     Failed to download the status list of the Android attestation keys
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">The exception of the HTTP client that describes the failure.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to download the status list of the Android attestation keys")]
    public static partial void WarnDownloadFailed(this ILogger logger, Exception exception);

    /// <summary>
    ///     The downloaded status list of the Android attestation keys is malformed
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The downloaded status list of the Android attestation keys is malformed")]
    public static partial void WarnDownloadedStatusListInvalid(this ILogger logger);

    /// <summary>
    ///     Failed to download the status list of the Android attestation keys because of an exception
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">The exception that interrupted the attempt.</param>
    [LoggerMessage(
        Level = LogLevel.Error,
        Message = "Failed to download the status list of the Android attestation keys because of an exception")]
    public static partial void ErrorDownloadAndUpsertFailed(this ILogger logger, Exception exception);

    /// <summary>
    ///     The status list of the Android attestation keys was downloaded after {FailedAttempts} consecutive unsuccessful attempts
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="failedAttempts">The number of consecutive unsuccessful attempts before the successful one.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The status list of the Android attestation keys was downloaded after {FailedAttempts} consecutive unsuccessful attempts")]
    public static partial void InfoDownloadedAfterFailedAttempts(this ILogger logger, int failedAttempts);

    /// <summary>
    ///     The next refresh of the status list of the Android attestation keys will be made in {IngestInterval} (at {NextRefreshTime:O})
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="ingestInterval">The delay before the next refresh.</param>
    /// <param name="nextRefreshTime">The time when the next refresh is made.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The next refresh of the status list of the Android attestation keys will be made in {IngestInterval} (at {NextRefreshTime:O})")]
    public static partial void InfoNextRefreshScheduled(this ILogger logger, TimeSpan ingestInterval, DateTimeOffset nextRefreshTime);

    /// <summary>
    ///     The next attempt to download the status list of the Android attestation keys will be made in {RetryInterval} (at {NextAttemptTime:O}), consecutive unsuccessful attempts: {FailedAttempts}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="retryInterval">The delay before the next attempt.</param>
    /// <param name="nextAttemptTime">The time when the next attempt is made.</param>
    /// <param name="failedAttempts">The number of consecutive unsuccessful attempts.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "The next attempt to download the status list of the Android attestation keys will be made in {RetryInterval} (at {NextAttemptTime:O}), consecutive unsuccessful attempts: {FailedAttempts}")]
    public static partial void InfoNextAttemptScheduled(this ILogger logger, TimeSpan retryInterval, DateTimeOffset nextAttemptTime, int failedAttempts);

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
    ///     The background ingestion of the status list of the Android attestation keys has stopped because of an exception, so the status list won't be updated until the application restarts
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">The exception that stopped the background ingestion.</param>
    [LoggerMessage(
        Level = LogLevel.Error,
        Message = "The background ingestion of the status list of the Android attestation keys has stopped because of an exception, so the status list won't be updated until the application restarts")]
    public static partial void ErrorIngestBackgroundServiceStopped(this ILogger logger, Exception exception);
}
