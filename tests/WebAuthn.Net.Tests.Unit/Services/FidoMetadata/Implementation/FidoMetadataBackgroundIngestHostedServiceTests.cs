using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using WebAuthn.Net.Configuration.DependencyInjection;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataBackgroundIngest;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataBackgroundIngest.Constants;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataIngestService;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;
using WebAuthn.Net.Services.Serialization.Json.Implementation;
using WebAuthn.Net.Storage.FidoMetadata;
using WebAuthn.Net.Storage.FidoMetadata.Implementation;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

// The delays between the attempts are controlled by the test: every delay is reported, and a positive one lasts until the test releases it,
// so the schedule (RetryInterval after a failure, IngestInterval after a success) is verified without waiting.
public class FidoMetadataBackgroundIngestHostedServiceTests
{
    private static readonly TimeSpan DefaultRetryInterval = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan DefaultIngestInterval = TimeSpan.FromDays(1);

    // A regression must fail a test rather than hang the test run: everything the tests wait for is limited in time.
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(10);
    private static readonly Assembly EmbeddedBlobAssembly = typeof(FidoMetadataBackgroundIngestHostedServiceTests).Assembly;
    private const string EmbeddedBlobResourceName = "WebAuthn.Net.DSL.Fakes.FakeResources.blob.jwt";

    private FidoMetadataBackgroundIngestHostedServiceOptions IngestOptions { get; set; } = null!;
    private ScriptedFidoMetadataProvider Provider { get; set; } = null!;
    private ObservableIngestStorage Storage { get; set; } = null!;
    private FakeFidoMetadataCounters Counters { get; set; } = null!;
    private FakeLogger<FidoMetadataBackgroundIngestHostedService> Logger { get; set; } = null!;
    private FakeLogger<DefaultFidoMetadataIngestService> IngestLogger { get; set; } = null!;
    private GatedHostedService Service { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        IngestOptions = new();
        Provider = new();
        Storage = new();
        Counters = new();
        Logger = new();
        IngestLogger = new();
        Service = CreateService(Provider);
    }

    [TearDown]
    public async Task TearDownServices()
    {
        // an attempt that is still waiting for a download (for example, after a failed assertion) must not hang the test run
        using var stopTimeout = new CancellationTokenSource(TestTimeout);
        await Service.StopAsync(stopTimeout.Token);
        Service.Dispose();
    }

    // ---------------------------------------------------------------------------------------------
    // The schedule: short retries until the blob is loaded, then long refreshes

    [Test]
    public async Task StartAsync_WithoutEmbeddedBlob_WaitsForFirstDownload_AndRefreshesEveryIngestInterval()
    {
        Provider.EnqueueSuccess(1);
        Provider.EnqueueSuccess(2);

        await StartServiceAsync();

        // the start has waited for the download
        Assert.That(Provider.DownloadCalls, Is.EqualTo(1));
        Assert.That(Storage.CurrentNo, Is.EqualTo(1));
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultIngestInterval));

        Service.ReleaseDelay();

        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultIngestInterval));
        Assert.That(Provider.DownloadCalls, Is.EqualTo(2));
        Assert.That(Storage.CurrentNo, Is.EqualTo(2));
        Assert.That(Logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
    }

    [Test]
    public async Task FailedAttempts_AreRetriedEveryRetryInterval_UntilBlobIsLoaded_ThenRefreshedEveryIngestInterval()
    {
        Provider.EnqueueFailure();
        Provider.EnqueueFailure();
        Provider.EnqueueSuccess(1);
        Provider.EnqueueFailure();

        await StartServiceAsync();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultRetryInterval));
        Service.ReleaseDelay();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultRetryInterval));
        Assert.That(Service.FailedAttempts, Is.EqualTo(2));
        Service.ReleaseDelay();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultIngestInterval));
        Assert.That(Service.FailedAttempts, Is.Zero);
        Assert.That(Storage.CurrentNo, Is.EqualTo(1));
        Service.ReleaseDelay();
        // a failed refresh falls back to the short retries
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultRetryInterval));

        Assert.That(Provider.DownloadCalls, Is.EqualTo(4));
        Assert.That(Storage.CurrentNo, Is.EqualTo(1), "a failed refresh keeps the metadata in use");
        var messages = Logger.Entries.Select(static x => x.Message).ToArray();
        Assert.That(messages.Count(static x => x.Contains("Failed to download metadata", StringComparison.Ordinal)), Is.EqualTo(3));
        // the count of the consecutive failures starts over after the blob is loaded
        Assert.That(messages.Count(static x => x.EndsWith("in 00:01:00, consecutive unsuccessful attempts: 1", StringComparison.Ordinal)), Is.EqualTo(2));
        Assert.That(messages, Has.One.EndsWith("in 00:01:00, consecutive unsuccessful attempts: 2"));
        Assert.That(messages, Has.One.EndsWith("consecutive unsuccessful attempts before it: 2"));
    }

    [Test]
    public async Task ConfiguredIntervals_AreUsed()
    {
        IngestOptions.RetryInterval = TimeSpan.FromSeconds(15);
        IngestOptions.IngestInterval = TimeSpan.FromHours(6);
        Provider.EnqueueFailure();
        Provider.EnqueueSuccess(1);

        await StartServiceAsync();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(TimeSpan.FromSeconds(15)));
        Service.ReleaseDelay();

        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(TimeSpan.FromHours(6)));
    }

    [Test]
    public async Task NonPositiveIntervals_AreReplacedWithDefaults_AndLoggedAsErrors()
    {
        // A zero retry interval would download the blob in a tight loop, and a negative one would make Task.Delay throw.
        IngestOptions.RetryInterval = TimeSpan.Zero;
        IngestOptions.IngestInterval = TimeSpan.FromHours(-1);
        Provider.EnqueueFailure();
        Provider.EnqueueSuccess(1);

        await StartServiceAsync();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultRetryInterval));
        Service.ReleaseDelay();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultIngestInterval));

        var errors = Logger.Entries.Where(static x => x.Level == LogLevel.Error).Select(static x => x.Message).ToArray();
        Assert.That(errors, Has.Length.EqualTo(2));
        Assert.That(errors[0], Does.Contain(nameof(FidoMetadataBackgroundIngestHostedServiceOptions.RetryInterval)));
        Assert.That(errors[1], Does.Contain(nameof(FidoMetadataBackgroundIngestHostedServiceOptions.IngestInterval)));
    }

    // ---------------------------------------------------------------------------------------------
    // A failure never stops the background ingestion

    [Test]
    public async Task ExceptionDuringBackgroundRefresh_IsLoggedAndCounted_AndRetried()
    {
        // For example, a resilience policy of the HttpClient throws when its circuit breaker is open.
        var exception = new InvalidOperationException("The circuit is now open and is not allowing calls.");
        Provider.EnqueueSuccess(1);
        Provider.EnqueueException(exception);
        Provider.EnqueueSuccess(2);

        await StartServiceAsync();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultIngestInterval));
        Service.ReleaseDelay();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultRetryInterval));

        var errors = Logger.Entries.Where(static x => x.Level == LogLevel.Error).ToArray();
        Assert.That(errors, Has.Length.EqualTo(1));
        Assert.That(errors[0].Exception, Is.SameAs(exception));
        Assert.That(Counters.IngestExceptions, Is.EqualTo(new[] { FidoMetadataBlobSources.FidoMetadataService }));

        Service.ReleaseDelay();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultIngestInterval));
        Assert.That(Storage.CurrentNo, Is.EqualTo(2));
    }

    [Test]
    public async Task ExceptionOfIngestStorage_IsLoggedAndCounted_AndRetried()
    {
        // For example, a timeout of a persistent storage.
        Provider.EnqueueSuccess(1);
        Provider.EnqueueSuccess(2);
        Provider.EnqueueSuccess(2);
        Storage.FailNextUpsert(new TimeoutException("The storage didn't respond in time"));

        await StartServiceAsync();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultRetryInterval));
        Assert.That(Counters.IngestExceptions, Is.EqualTo(new[] { FidoMetadataBlobSources.FidoMetadataService }));
        Service.ReleaseDelay();

        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultIngestInterval));
        Assert.That(Storage.CurrentNo, Is.EqualTo(2));
    }

    [Test]
    public async Task OperationCanceledExceptionThatTheHostDidNotRequest_IsTreatedAsFailure()
    {
        // Only the cancellation requested by the host stops the background ingestion; a timeout implemented through a cancellation is a failure like any other.
        Provider.EnqueueSuccess(1);
        Provider.EnqueueException(new OperationCanceledException("A timeout of a custom component"));
        Provider.EnqueueSuccess(2);

        await StartServiceAsync();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultIngestInterval));
        Service.ReleaseDelay();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultRetryInterval));
        Service.ReleaseDelay();

        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultIngestInterval));
        Assert.That(Storage.CurrentNo, Is.EqualTo(2));
    }

    [Test]
    public async Task ThrowExceptionOnFailure_DoesNotApplyToBackgroundRefresh()
    {
        // Previously the flag was read in the background loop too, so the first failed refresh silently stopped the updates of the metadata forever.
        IngestOptions.ThrowExceptionOnFailure = true;
        Provider.EnqueueSuccess(1);
        Provider.EnqueueFailure();
        Provider.EnqueueSuccess(2);

        await StartServiceAsync();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultIngestInterval));
        Service.ReleaseDelay();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultRetryInterval));
        Service.ReleaseDelay();

        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultIngestInterval));
        Assert.That(Storage.CurrentNo, Is.EqualTo(2));
        Assert.That(Logger.Entries.Where(static x => x.Level == LogLevel.Error), Is.Empty);
    }

    [Test]
    public async Task StopAsync_StopsBackgroundIngestion_WithoutErrors()
    {
        Provider.EnqueueSuccess(1);
        await StartServiceAsync();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultIngestInterval));

        await Service.StopAsync(CancellationToken.None);

        Assert.That(Service.BackgroundTask!.IsCompleted, Is.True);
        Assert.That(Provider.DownloadCalls, Is.EqualTo(1));
        Assert.That(Logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
        Assert.That(Counters.IngestExceptions, Is.Empty);
    }

    // ---------------------------------------------------------------------------------------------
    // The start-up without the embedded blob

    [Test]
    public async Task StartAsync_WhenFirstDownloadFails_StartsAndRetries()
    {
        Provider.EnqueueFailure();

        await StartServiceAsync();

        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultRetryInterval));
        Assert.That(Storage.CurrentNo, Is.Null);
        Assert.That(Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message), Has.One.Contains("Failed to download metadata"));
    }

    [Test]
    public async Task StartAsync_WhenFirstDownloadThrows_DoesNotBreakStart_AndRetries()
    {
        var exception = new HttpRequestException("Unexpected exception of a delegating handler");
        Provider.EnqueueException(exception);

        await StartServiceAsync();

        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultRetryInterval));
        Assert.That(Logger.Entries.Single(static x => x.Level == LogLevel.Error).Exception, Is.SameAs(exception));
        Assert.That(Counters.IngestExceptions, Is.EqualTo(new[] { FidoMetadataBlobSources.FidoMetadataService }));
    }

    [Test]
    public async Task StartAsync_WhenFirstDownloadCannotBeDecoded_StartsAndRetries()
    {
        Provider.EnqueueUndecodable();

        await StartServiceAsync();

        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultRetryInterval));
        Assert.That(Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message), Has.One.Contains("Failed to decode data downloaded"));
    }

    [Test]
    public async Task StartAsync_WhenNoMetadataCanBeLoaded_AndThrowExceptionOnFailureIsSet_Throws()
    {
        IngestOptions.ThrowExceptionOnFailure = true;
        Provider.EnqueueFailure();

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await StartServiceAsync());

        Assert.That(Service.BackgroundTask, Is.Null, "the background ingestion doesn't start when the start of the application fails");
    }

    [Test]
    public async Task StartAsync_WhenFirstDownloadThrows_AndThrowExceptionOnFailureIsSet_ThrowsInvalidOperationException()
    {
        IngestOptions.ThrowExceptionOnFailure = true;
        Provider.EnqueueException(new HttpRequestException("Unexpected exception of a delegating handler"));

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await StartServiceAsync());
    }

    // ---------------------------------------------------------------------------------------------
    // The start-up with the embedded blob

    [Test]
    public async Task StartAsync_WithEmbeddedBlob_IngestsItFirst_AndDoesNotWaitForFidoMetadataService()
    {
        ConfigureEmbeddedBlob();
        Provider.EmbeddedPayload = CreatePayload(291);
        var download = new TaskCompletionSource<Result<MetadataBLOBPayloadJSON>>(TaskCreationOptions.RunContinuationsAsynchronously);
        Provider.EnqueueDownload(cancellationToken => download.Task.WaitAsync(cancellationToken));

        await StartServiceAsync();

        // the start has completed with the embedded metadata, the download from the FIDO Metadata Service is still in progress
        Assert.That(Storage.CurrentNo, Is.EqualTo(291));
        Assert.That(Provider.EmbeddedRequests, Is.EqualTo(new[] { EmbeddedBlobResourceName }));
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(TimeSpan.Zero));
        await Provider.WaitForDownloadAsync(1);
        Assert.That(download.Task.IsCompleted, Is.False);

        download.SetResult(Result<MetadataBLOBPayloadJSON>.Success(CreatePayload(292)));

        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultIngestInterval));
        Assert.That(Storage.CurrentNo, Is.EqualTo(292));
        Assert.That(IngestLogger.Entries.Select(static x => x.Message), Has.One.Contains("(no: 291) with 1 entries embedded in the application was ingested"));
    }

    [Test]
    public async Task StartAsync_WithEmbeddedBlob_WhenFidoMetadataServiceFails_KeepsEmbeddedMetadata_AndRetries()
    {
        // The embedded metadata is available, so the start doesn't fail even if the application shouldn't start without metadata.
        IngestOptions.ThrowExceptionOnFailure = true;
        ConfigureEmbeddedBlob();
        Provider.EmbeddedPayload = CreatePayload(291);
        Provider.EnqueueFailure();
        Provider.EnqueueFailure();

        await StartServiceAsync();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(TimeSpan.Zero));
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultRetryInterval));
        Service.ReleaseDelay();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultRetryInterval));

        Assert.That(Storage.CurrentNo, Is.EqualTo(291));
        Assert.That(Service.FailedAttempts, Is.EqualTo(2));
    }

    [Test]
    public async Task StartAsync_WhenEmbeddedBlobIsNotConfigured_DoesNotLoadIt()
    {
        Provider.EnqueueSuccess(1);

        await StartServiceAsync();

        Assert.That(Provider.EmbeddedRequests, Is.Empty);
        Assert.That(Logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
    }

    [Test]
    public async Task StartAsync_WhenEmbeddedBlobIsRejected_WaitsForFidoMetadataService()
    {
        // The provider has logged and counted the reason; the start waits for the FIDO Metadata Service as if there were no embedded blob.
        ConfigureEmbeddedBlob();
        Provider.EmbeddedPayload = null;
        Provider.EnqueueSuccess(292);

        await StartServiceAsync();

        Assert.That(Provider.EmbeddedRequests, Has.Count.EqualTo(1));
        Assert.That(Provider.DownloadCalls, Is.EqualTo(1));
        Assert.That(Storage.CurrentNo, Is.EqualTo(292));
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultIngestInterval));
    }

    [Test]
    public async Task StartAsync_WhenEmbeddedBlobCannotBeDecoded_Warns_AndWaitsForFidoMetadataService()
    {
        ConfigureEmbeddedBlob();
        Provider.EmbeddedPayload = CreateUndecodablePayload();
        Provider.EnqueueSuccess(292);

        await StartServiceAsync();

        Assert.That(Provider.DownloadCalls, Is.EqualTo(1));
        Assert.That(Storage.CurrentNo, Is.EqualTo(292));
        Assert.That(Logger.Entries.Single(static x => x.Level == LogLevel.Warning).Message, Does.Contain("Failed to decode the FIDO Metadata Service blob embedded in the application"));
    }

    [Test]
    public async Task StartAsync_WhenLoadingEmbeddedBlobThrows_LogsErrorAndCounts_AndWaitsForFidoMetadataService()
    {
        // For example, a custom provider that doesn't support the embedded blob (the default interface method throws NotSupportedException).
        ConfigureEmbeddedBlob();
        var exception = new NotSupportedException("The provider doesn't support the embedded blob");
        Provider.EmbeddedException = exception;
        Provider.EnqueueSuccess(292);

        await StartServiceAsync();

        Assert.That(Provider.DownloadCalls, Is.EqualTo(1));
        Assert.That(Storage.CurrentNo, Is.EqualTo(292));
        var error = Logger.Entries.Single(static x => x.Level == LogLevel.Error);
        Assert.That(error.Message, Does.Contain("embedded in the application"));
        Assert.That(error.Exception, Is.SameAs(exception));
        Assert.That(Counters.IngestExceptions, Is.EqualTo(new[] { FidoMetadataBlobSources.Embedded }));
    }

    [Test]
    public async Task StartAsync_WhenEmbeddedBlobIsNotNewerThanMetadataInUse_KeepsMetadataInUse_AndDoesNotReportRollback()
    {
        // A persistent storage keeps the blob downloaded before the restart of the application: the older embedded blob is expected, it is not a rollback.
        Storage.CurrentNo = 300;
        ConfigureEmbeddedBlob();
        Provider.EmbeddedPayload = CreatePayload(291);
        var download = new TaskCompletionSource<Result<MetadataBLOBPayloadJSON>>(TaskCreationOptions.RunContinuationsAsynchronously);
        Provider.EnqueueDownload(cancellationToken => download.Task.WaitAsync(cancellationToken));

        await StartServiceAsync();

        // the metadata is available, so the start doesn't wait for the FIDO Metadata Service
        Assert.That(Storage.CurrentNo, Is.EqualTo(300));
        Assert.That(Storage.Upserts, Is.Zero);
        Assert.That(Counters.BlobsRejectedDueToRollback, Is.Zero);
        Assert.That(IngestLogger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
        Assert.That(IngestLogger.Entries.Single(static x => x.Level == LogLevel.Information).Message, Does.Contain("(no: 291) embedded in the application was not ingested because the metadata in use (no: 300) is not older"));
        download.SetResult(Result<MetadataBLOBPayloadJSON>.Success(CreatePayload(301)));
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(TimeSpan.Zero));
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultIngestInterval));
        Assert.That(Storage.CurrentNo, Is.EqualTo(301));
    }

    [Test]
    public async Task StartAsync_WithGenuineEmbeddedBlob_WhenFidoMetadataServiceIsUnavailable_StartsWithEmbeddedMetadata()
    {
        // The whole chain with the default implementations: the genuine blob (no: 291) embedded in the test assembly is verified, decoded and ingested,
        // while every download from the FIDO Metadata Service fails.
        using var configurationManager = new ConfigurationManager();
        var webAuthnOptions = FakeWebAuthnOptionsFactory.Create(configurationManager);
        var webAuthnOptionsMonitor = new FakeOptionsMonitor<WebAuthnOptions>(webAuthnOptions);
        var providerCounters = new FakeFidoMetadataCounters();
        var provider = new DefaultFidoMetadataProvider(
            webAuthnOptionsMonitor,
            new DefaultSafeJsonSerializer(NullLogger<DefaultSafeJsonSerializer>.Instance),
            new UnavailableFidoMetadataHttpClient(),
            new FakeTimeProvider(DateTimeOffset.Parse("2026-10-26T00:00:00.0000000+00:00", CultureInfo.InvariantCulture)),
            providerCounters,
            NullLogger<DefaultFidoMetadataProvider>.Instance);
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        ConfigureEmbeddedBlob();
        await Service.StopAsync(CancellationToken.None);
        Service.Dispose();
        Service = new(
            new FakeOptionsMonitor<FidoMetadataBackgroundIngestHostedServiceOptions>(IngestOptions),
            new DefaultFidoMetadataIngestService(storage, Counters, IngestLogger),
            provider,
            CreateDecoder(),
            Counters,
            Logger);

        await StartServiceAsync();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(TimeSpan.Zero));
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(DefaultRetryInterval));

        await using var context = new FakeWebAuthnContext(null, new());
        var yubiKey5Series = await storage.FindByAaguidAsync(context, Guid.Parse("cb69481e-8ff7-4039-93ec-0a2729a154a8"), CancellationToken.None);
        Assert.That(yubiKey5Series.HasError, Is.False);
        Assert.That(await storage.GetCurrentBlobNoAsync(CancellationToken.None), Is.EqualTo(291));
        Assert.Multiple(() =>
        {
            Assert.That(providerCounters.SuccessfulEmbeddedLoadEnds, Is.EqualTo(1));
            Assert.That(providerCounters.FailedDownloadEnds, Is.EqualTo(1));
            Assert.That(Counters.IngestExceptions, Is.Empty);
        });
    }

    // ---------------------------------------------------------------------------------------------
    // The delay

    [Test]
    public async Task DelayAsync_WithIntervalBeyondLimitOfTaskDelay_WaitsInParts()
    {
        // Task.Delay throws ArgumentOutOfRangeException for a delay longer than about 49.7 days; a long interval must not break the background ingestion.
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.CatchAsync<OperationCanceledException>(async () => await Service.InvokeDelayAsync(TimeSpan.FromDays(60), cts.Token));
    }

    [Test]
    public async Task AddWebAuthnCore_RegistersHostedService_ThatContainerCanConstruct_WithConfiguredOptions()
    {
        // The hosted service is constructed by the container when the host starts, so a dependency that is not registered would break the start of the application.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddWebAuthnCore<FakeWebAuthnContext>(
                configureBackgroundIngest: ingest =>
                {
                    ingest.RetryInterval = TimeSpan.FromSeconds(30);
                    ingest.EmbeddedBlob = new(EmbeddedBlobAssembly, EmbeddedBlobResourceName);
                })
            .AddDefaultFidoMetadataStorage();
        await using var serviceProvider = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = false,
            ValidateScopes = true
        });

        var hostedServices = serviceProvider.GetServices<IHostedService>().OfType<FidoMetadataBackgroundIngestHostedService>().ToArray();
        var options = serviceProvider.GetRequiredService<IOptionsMonitor<FidoMetadataBackgroundIngestHostedServiceOptions>>().CurrentValue;

        Assert.That(hostedServices, Has.Length.EqualTo(1));
        Assert.Multiple(() =>
        {
            Assert.That(options.RetryInterval, Is.EqualTo(TimeSpan.FromSeconds(30)));
            Assert.That(options.IngestInterval, Is.EqualTo(DefaultIngestInterval));
            Assert.That(options.EmbeddedBlob?.Assembly, Is.SameAs(EmbeddedBlobAssembly));
            Assert.That(options.EmbeddedBlob?.ResourceName, Is.EqualTo(EmbeddedBlobResourceName));
        });
    }

    [Test]
    public void DefaultOptions_RetryEveryMinute_AndRefreshEveryDay()
    {
        var options = new FidoMetadataBackgroundIngestHostedServiceOptions();

        Assert.Multiple(() =>
        {
            Assert.That(options.RetryInterval, Is.EqualTo(TimeSpan.FromMinutes(1)));
            Assert.That(options.IngestInterval, Is.EqualTo(TimeSpan.FromDays(1)));
            Assert.That(options.ThrowExceptionOnFailure, Is.False);
            Assert.That(options.EmbeddedBlob, Is.Null);
        });
    }

    private Task StartServiceAsync()
    {
        return Service.StartAsync(CancellationToken.None).WaitAsync(TestTimeout);
    }

    private void ConfigureEmbeddedBlob()
    {
        IngestOptions.EmbeddedBlob = new(EmbeddedBlobAssembly, EmbeddedBlobResourceName);
    }

    private GatedHostedService CreateService(IFidoMetadataProvider provider)
    {
        return new(
            new FakeOptionsMonitor<FidoMetadataBackgroundIngestHostedServiceOptions>(IngestOptions),
            new DefaultFidoMetadataIngestService(Storage, Counters, IngestLogger),
            provider,
            CreateDecoder(),
            Counters,
            Logger);
    }

    private DefaultFidoMetadataDecoder CreateDecoder()
    {
        return new(
            new DefaultEnumMemberAttributeSerializer<UserVerificationMethod>(),
            new DefaultEnumMemberAttributeSerializer<ProtocolFamily>(),
            new DefaultEnumMemberAttributeSerializer<AuthenticationAlgorithm>(),
            new DefaultEnumMemberAttributeSerializer<PublicKeyRepresentationFormat>(),
            new DefaultEnumMemberAttributeSerializer<AuthenticatorAttestationType>(),
            new DefaultEnumMemberAttributeSerializer<KeyProtectionType>(),
            new DefaultEnumMemberAttributeSerializer<MatcherProtectionType>(),
            new DefaultEnumMemberAttributeSerializer<AuthenticatorAttachmentHint>(),
            new DefaultEnumMemberAttributeSerializer<TransactionConfirmationDisplayType>(),
            new DefaultEnumMemberAttributeSerializer<AuthenticatorStatus>(),
            Counters,
            NullLogger<DefaultFidoMetadataDecoder>.Instance);
    }

    private static MetadataBLOBPayloadJSON CreatePayload(long no)
    {
        return FakeMetadataBlobPayloadJsonFactory.Create(payload => payload["no"] = no);
    }

    // a payload without the 'entries' member, which the decoder rejects
    private static MetadataBLOBPayloadJSON CreateUndecodablePayload()
    {
        return FakeMetadataBlobPayloadJsonFactory.Create(static payload => payload.Remove("entries"));
    }

    private sealed class GatedHostedService : FidoMetadataBackgroundIngestHostedService
    {
        private readonly Channel<TimeSpan> _delays = Channel.CreateUnbounded<TimeSpan>();
        private readonly SemaphoreSlim _releases = new(0);

        public GatedHostedService(
            IOptionsMonitor<FidoMetadataBackgroundIngestHostedServiceOptions> options,
            IFidoMetadataIngestService metadataIngestService,
            IFidoMetadataProvider provider,
            IFidoMetadataDecoder decoder,
            FakeFidoMetadataCounters counters,
            ILogger<FidoMetadataBackgroundIngestHostedService> logger)
            : base(options, metadataIngestService, provider, decoder, counters, logger)
        {
        }

        public int FailedAttempts => ConsecutiveFailedAttempts;

        public Task? BackgroundTask => PeriodicBackgroundUpdateTask;

        public async Task<TimeSpan> WaitForDelayAsync()
        {
            using var timeout = new CancellationTokenSource(TestTimeout);
            return await _delays.Reader.ReadAsync(timeout.Token);
        }

        public void ReleaseDelay()
        {
            _releases.Release();
        }

        public Task InvokeDelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            return base.DelayAsync(delay, cancellationToken);
        }

        protected override async Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            _delays.Writer.TryWrite(delay);
            if (delay > TimeSpan.Zero)
            {
                await _releases.WaitAsync(cancellationToken);
                return;
            }

            await base.DelayAsync(delay, cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing)
            {
                _releases.Dispose();
            }
        }
    }

    private sealed class ScriptedFidoMetadataProvider : IFidoMetadataProvider
    {
        private readonly ConcurrentQueue<Func<CancellationToken, Task<Result<MetadataBLOBPayloadJSON>>>> _downloads = new();
        private readonly ConcurrentQueue<string> _embeddedRequests = new();
        private readonly Channel<int> _downloadCalls = Channel.CreateUnbounded<int>();
        private int _downloadCallsCount;

        public MetadataBLOBPayloadJSON? EmbeddedPayload { get; set; }

        public Exception? EmbeddedException { get; set; }

        public int DownloadCalls => Volatile.Read(ref _downloadCallsCount);

        public IReadOnlyCollection<string> EmbeddedRequests => _embeddedRequests.ToArray();

        public Task<Result<MetadataBLOBPayloadJSON>> DownloadMetadataAsync(CancellationToken cancellationToken)
        {
            var call = Interlocked.Increment(ref _downloadCallsCount);
            _downloadCalls.Writer.TryWrite(call);
            // an unexpected call fails, as an unavailable FIDO Metadata Service would
            return _downloads.TryDequeue(out var download)
                ? download(cancellationToken)
                : Task.FromResult(Result<MetadataBLOBPayloadJSON>.Fail());
        }

        public Task<Result<MetadataBLOBPayloadJSON>> LoadEmbeddedMetadataAsync(FidoMetadataEmbeddedBlob embeddedBlob, CancellationToken cancellationToken)
        {
            _embeddedRequests.Enqueue(embeddedBlob.ResourceName);
            if (EmbeddedException is not null)
            {
                throw EmbeddedException;
            }

            return Task.FromResult(EmbeddedPayload is not null
                ? Result<MetadataBLOBPayloadJSON>.Success(EmbeddedPayload)
                : Result<MetadataBLOBPayloadJSON>.Fail());
        }

        public void EnqueueDownload(Func<CancellationToken, Task<Result<MetadataBLOBPayloadJSON>>> download)
        {
            _downloads.Enqueue(download);
        }

        public void EnqueueSuccess(long no)
        {
            var payload = CreatePayload(no);
            EnqueueDownload(_ => Task.FromResult(Result<MetadataBLOBPayloadJSON>.Success(payload)));
        }

        public void EnqueueUndecodable()
        {
            var payload = CreateUndecodablePayload();
            EnqueueDownload(_ => Task.FromResult(Result<MetadataBLOBPayloadJSON>.Success(payload)));
        }

        public void EnqueueFailure()
        {
            EnqueueDownload(static _ => Task.FromResult(Result<MetadataBLOBPayloadJSON>.Fail()));
        }

        public void EnqueueException(Exception exception)
        {
            EnqueueDownload(_ => throw exception);
        }

        public async Task WaitForDownloadAsync(int call)
        {
            using var timeout = new CancellationTokenSource(TestTimeout);
            int lastCall;
            do
            {
                lastCall = await _downloadCalls.Reader.ReadAsync(timeout.Token);
            }
            while (lastCall < call);
        }
    }

    // An ingest storage that tracks the serial number of the stored blob, like a persistent storage, and can fail on demand.
    private sealed class ObservableIngestStorage : IFidoMetadataIngestStorage
    {
        private Exception? _nextUpsertException;

        public long? CurrentNo { get; set; }

        public int Upserts { get; private set; }

        public Task UpsertAsync(MetadataBlobPayload metadataBlob, CancellationToken cancellationToken)
        {
            var exception = Interlocked.Exchange(ref _nextUpsertException, null);
            if (exception is not null)
            {
                throw exception;
            }

            Upserts++;
            CurrentNo = metadataBlob.No;
            return Task.CompletedTask;
        }

        public Task<long?> GetCurrentBlobNoAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(CurrentNo);
        }

        public void FailNextUpsert(Exception exception)
        {
            _nextUpsertException = exception;
        }
    }

    private sealed class UnavailableFidoMetadataHttpClient : IFidoMetadataHttpClient
    {
        public Task<string> DownloadMetadataAsync(CancellationToken cancellationToken)
        {
            throw new HttpRequestException("Response status code does not indicate success: 503 (Service Unavailable).");
        }
    }

    private sealed class FakeOptionsMonitor<TOptions> : IOptionsMonitor<TOptions>
    {
        public FakeOptionsMonitor(TOptions currentValue)
        {
            CurrentValue = currentValue;
        }

        public TOptions CurrentValue { get; }

        public TOptions Get(string? name)
        {
            return CurrentValue;
        }

        public IDisposable? OnChange(Action<TOptions, string?> listener)
        {
            return null;
        }
    }
}
