using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataBackgroundIngest;

public class FidoMetadataBackgroundIngestHostedService : IHostedService, IDisposable
{
    public FidoMetadataBackgroundIngestHostedService(
        IOptionsMonitor<FidoMetadataBackgroundIngestHostedServiceOptions> options,
        IFidoMetadataIngestService metadataIngestService,
        IFidoMetadataProvider provider,
        IFidoMetadataDecoder decoder)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(metadataIngestService);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(decoder);
        MetadataIngestService = metadataIngestService;
        Provider = provider;
        Decoder = decoder;
        Options = options;
    }

    protected Task? PeriodicBackgroundUpdateTask { get; set; }
    protected CancellationTokenSource? StoppingCts { get; set; }
    protected IFidoMetadataIngestService MetadataIngestService { get; }
    protected IFidoMetadataProvider Provider { get; }
    protected IFidoMetadataDecoder Decoder { get; }
    protected IOptionsMonitor<FidoMetadataBackgroundIngestHostedServiceOptions> Options { get; }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }


    public virtual async Task StartAsync(CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return;
        }

        await DownloadAndUpsertMetadataAsync(cancellationToken);
        await StartBackgroundIngestAsync(cancellationToken);
    }

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
            StoppingCts?.Cancel();
        }
        finally
        {
            // Wait until the task completes or the stop token triggers
            await Task.WhenAny(PeriodicBackgroundUpdateTask, Task.Delay(Timeout.Infinite, cancellationToken)).ConfigureAwait(false);
        }
    }

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

    protected virtual async Task BackgroundIngestAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(Options.CurrentValue.IngestInterval, stoppingToken);
            await DownloadAndUpsertMetadataAsync(stoppingToken);
        }
    }

    protected virtual async Task DownloadAndUpsertMetadataAsync(CancellationToken stoppingToken)
    {
        stoppingToken.ThrowIfCancellationRequested();
        var metadataResult = await Provider.DownloadMetadataAsync(stoppingToken);
        if (metadataResult.HasError)
        {
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
            if (Options.CurrentValue.ThrowExceptionOnFailure)
            {
                throw new InvalidOperationException("Failed to decode data downloaded from the FIDO Metadata Service");
            }

            return;
        }

        await MetadataIngestService.UpsertAsync(decodeResult.Ok, stoppingToken);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            PeriodicBackgroundUpdateTask?.Dispose();
            StoppingCts?.Dispose();
        }
    }
}
