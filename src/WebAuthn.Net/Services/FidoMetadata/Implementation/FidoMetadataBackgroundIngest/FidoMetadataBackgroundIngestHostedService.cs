using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataBackgroundIngest;

/// <summary>
///     A service for background ingestion of metadata from the FIDO Metadata Service and their periodic update.
/// </summary>
public class FidoMetadataBackgroundIngestHostedService : IHostedService, IDisposable
{
    /// <summary>
    ///     Constructs <see cref="FidoMetadataBackgroundIngestHostedService" />.
    /// </summary>
    /// <param name="options">An accessor for obtaining the current value of options that set the parameters for the background ingest.</param>
    /// <param name="metadataIngestService">The ingestion service for metadata obtained from the FIDO Metadata Service, designed to store data from the retrieved blob.</param>
    /// <param name="provider">Provider of metadata from FIDO Metadata Service.</param>
    /// <param name="decoder">Decoder for data received from the FIDO Metadata Service's blob.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public FidoMetadataBackgroundIngestHostedService(
        IOptionsMonitor<FidoMetadataBackgroundIngestHostedServiceOptions> options,
        IFidoMetadataIngestService metadataIngestService,
        IFidoMetadataProvider provider,
        IFidoMetadataDecoder decoder,
        ILogger<FidoMetadataBackgroundIngestHostedService> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(metadataIngestService);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(logger);
        Options = options;
        MetadataIngestService = metadataIngestService;
        Provider = provider;
        Decoder = decoder;
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
    ///     Logger.
    /// </summary>
    protected ILogger<FidoMetadataBackgroundIngestHostedService> Logger { get; }

    /// <inheritdoc />
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <inheritdoc />
    public virtual async Task StartAsync(CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return;
        }

        await DownloadAndUpsertMetadataAsync(cancellationToken);
        await StartBackgroundIngestAsync(cancellationToken);
    }

    /// <inheritdoc />
    public virtual async Task StopAsync(CancellationToken cancellationToken)
    {
        // Stop called without start
        if (PeriodicBackgroundUpdateTask == null)
        {
            return;
        }

        try
        {
            // Signal cancellation to the executing method
            var stoppingCts = StoppingCts;
#if NET6_0
            stoppingCts?.Cancel();
#else
            if (stoppingCts is not null)
            {
                await stoppingCts.CancelAsync();
            }
#endif
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
    /// <param name="cancellationToken">Indicates that the start process has been aborted.</param>
    /// <returns>An asynchronous task that performs metadata update in the background.</returns>
    protected virtual Task StartBackgroundIngestAsync(CancellationToken cancellationToken)
    {
        // Create linked token to allow cancelling executing task from provided token
        StoppingCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        // Store the task we're executing
        PeriodicBackgroundUpdateTask = BackgroundIngestAsync(StoppingCts.Token);

        // If the task is completed then return it, this will bubble cancellation and failure to the caller
        if (PeriodicBackgroundUpdateTask.IsCompleted)
        {
            return PeriodicBackgroundUpdateTask;
        }

        // Otherwise it's running
        return Task.CompletedTask;
    }

    /// <summary>
    ///     Asynchronously downloads and ingests metadata in an infinite loop at an interval specified in the <see cref="Options" />, until the <paramref name="stoppingToken" /> triggers.
    /// </summary>
    /// <param name="stoppingToken">Cancellation token for an asynchronous operation.</param>
    protected virtual async Task BackgroundIngestAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(Options.CurrentValue.IngestInterval, stoppingToken);
            await DownloadAndUpsertMetadataAsync(stoppingToken);
        }
    }

    /// <summary>
    ///     Asynchronously downloads and ingests metadata from the FIDO Metadata Service
    /// </summary>
    /// <param name="stoppingToken">Cancellation token for an asynchronous operation.</param>
    /// <exception cref="InvalidOperationException">Failed to download or decode the data. Only triggers if the corresponding flag is set in the <see cref="Options" />.</exception>
    protected virtual async Task DownloadAndUpsertMetadataAsync(CancellationToken stoppingToken)
    {
        stoppingToken.ThrowIfCancellationRequested();
        var metadataResult = await Provider.DownloadMetadataAsync(stoppingToken);
        if (metadataResult.HasError)
        {
            Logger.FailedToDownload();
            if (Options.CurrentValue.ThrowExceptionOnFailure)
            {
                throw new InvalidOperationException("Failed to download metadata from the FIDO Metadata Service");
            }

            return;
        }

        var rawMetadata = metadataResult.Ok;
        var decodeResult = Decoder.Decode(rawMetadata);
        if (decodeResult.HasError)
        {
            Logger.FailedToDecode();
            if (Options.CurrentValue.ThrowExceptionOnFailure)
            {
                throw new InvalidOperationException("Failed to decode data downloaded from the FIDO Metadata Service");
            }

            return;
        }

        await MetadataIngestService.UpsertAsync(decodeResult.Ok, stoppingToken);
    }

    /// <summary>
    ///     Releases all resources currently used by this <see cref="FidoMetadataBackgroundIngestHostedService" /> instance.
    /// </summary>
    /// <param name="disposing"><see langword="true" /> if this method is being invoked by the <see cref="Dispose()" /> method, otherwise <see langword="false" />.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            PeriodicBackgroundUpdateTask?.Dispose();
            StoppingCts?.Dispose();
        }
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
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to download metadata from the FIDO Metadata Service")]
    public static partial void FailedToDownload(this ILogger logger);

    /// <summary>
    ///     Failed to decode data downloaded from the FIDO Metadata Service.
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode data downloaded from the FIDO Metadata Service")]
    public static partial void FailedToDecode(this ILogger logger);
}
