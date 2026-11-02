using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using WebAuthn.Net.Configuration.DependencyInjection;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusDecoder;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusIngest;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusIngest.Constants;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.AndroidKey;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidKey;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Json.Implementation;
using WebAuthn.Net.Storage.AndroidKeyAttestationStatus;
using WebAuthn.Net.Storage.AndroidKeyAttestationStatus.Implementation;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation;

public class AndroidKeyAttestationStatusIngestBackgroundServiceTests
{
    private const string EmbeddedStatusListResourceName = "WebAuthn.Net.DSL.Fakes.FakeResources.android-key-status.json";
    private const string StatusListWithTwoEntries = """{"entries":{"1a":{"status":"REVOKED","reason":"KEY_COMPROMISE"},"2b":{"status":"SUSPENDED"}}}""";
    private const string StatusListWithOneEntry = """{"entries":{"3c":{"status":"REVOKED"}}}""";
    private static readonly Assembly EmbeddedStatusListAssembly = typeof(AndroidKeyAttestationStatusIngestBackgroundServiceTests).Assembly;
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(30);
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-02T10:00:00Z", System.Globalization.CultureInfo.InvariantCulture);

    private WebAuthnOptions WebAuthnOptions { get; set; } = null!;
    private FakeStatusHttpClient HttpClient { get; set; } = null!;
    private FakeAndroidKeyAttestationStatusStorage Storage { get; set; } = null!;
    private FakeAndroidKeyAttestationStatusCounters Counters { get; set; } = null!;
    private FakeLogger<AndroidKeyAttestationStatusIngestBackgroundService> Logger { get; set; } = null!;
    private GatedBackgroundService Service { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        WebAuthnOptions = new();
        HttpClient = new();
        Storage = new(null);
        Counters = new();
        Logger = new();
        var decoder = new DefaultAndroidKeyAttestationStatusDecoder(
            new DefaultSafeJsonSerializer(new FakeLogger<DefaultSafeJsonSerializer>()),
            Counters,
            new FakeLogger<DefaultAndroidKeyAttestationStatusDecoder>());
        Service = new(new OptionsMonitorStub(WebAuthnOptions), HttpClient, decoder, Storage, new FakeTimeProvider(Now), Counters, Logger);
    }

    [TearDown]
    public async Task TearDownServices()
    {
        await Service.StopAsync(CancellationToken.None).WaitAsync(TestTimeout);
        Service.Dispose();
    }

    [Test]
    public async Task StartAsync_DownloadsStatusList_AndSchedulesNextRefresh()
    {
        HttpClient.EnqueueSuccess(StatusListWithTwoEntries);

        await StartServiceAsync();

        var statusList = await Storage.GetAsync(CancellationToken.None);
        Assert.Multiple(() =>
        {
            Assert.That(HttpClient.Calls, Is.EqualTo(1), "the start waits for the first download");
            Assert.That(statusList?.Entries.Keys, Is.EquivalentTo(Values("1a", "2b")));
            Assert.That(Information(), Is.EqualTo(Values(
                "The ingestion of the status list of the Android attestation keys has started",
                "The status list of the Android attestation keys was downloaded: 2 entries",
                "The next refresh of the status list of the Android attestation keys will be made in 1.00:00:00 (at 2026-11-03T10:00:00.0000000+00:00)")));
            Assert.That(Warnings(), Is.Empty);
        });
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(TimeSpan.FromDays(1)));
    }

    [Test]
    public async Task StartAsync_Starts_WhenFirstDownloadFails_AndRetriesUntilDownloaded()
    {
        HttpClient.EnqueueFailure(new HttpRequestException("Response status code does not indicate success: 503 (Service Unavailable)."));

        await StartServiceAsync();

        Assert.Multiple(() =>
        {
            Assert.That(Storage.StatusList, Is.Null);
            Assert.That(Counters.DownloadFailures, Is.EqualTo(Values(AndroidKeyAttestationStatusListFailures.RequestFailed)));
            Assert.That(Warnings(), Is.EqualTo(Values("Failed to download the status list of the Android attestation keys")));
            Assert.That(Information(), Has.One.EqualTo("The next attempt to download the status list of the Android attestation keys will be made in 00:01:00 (at 2026-11-02T10:01:00.0000000+00:00), consecutive unsuccessful attempts: 1"));
        });
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(TimeSpan.FromMinutes(1)));

        HttpClient.EnqueueSuccess(StatusListWithOneEntry);
        Service.ReleaseDelay();

        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(TimeSpan.FromDays(1)));
        Assert.Multiple(() =>
        {
            Assert.That(Storage.StatusList?.Entries.Keys, Is.EquivalentTo(Values("3c")));
            Assert.That(Information(), Has.One.EqualTo("The status list of the Android attestation keys was downloaded after 1 consecutive unsuccessful attempts"));
        });
    }

    [Test]
    public async Task StartAsync_LoadsEmbeddedStatusList_AndDownloadsStatusListRightAway()
    {
        WebAuthnOptions.AttestationStatements.AndroidKey.StatusList.EmbeddedStatusList = new(EmbeddedStatusListAssembly, EmbeddedStatusListResourceName);
        var downloaded = HttpClient.EnqueueSuccess(StatusListWithOneEntry, true);

        await StartServiceAsync();

        Assert.Multiple(() =>
        {
            Assert.That(Storage.StatusList?.Entries.Keys, Is.EquivalentTo(Values("6681152659205225093", "c35747a084470c3135aeefe2b8d40cd6", "c8966fcb2fbb0d7a")));
            Assert.That(Information(), Has.One.EqualTo("The status list of the Android attestation keys embedded in the application was loaded: 3 entries"));
        });
        // the start doesn't wait for the download: the background ingestion downloads the status list right away
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(TimeSpan.Zero));
        downloaded!.TrySetResult();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(TimeSpan.FromDays(1)));
        Assert.That(Storage.StatusList?.Entries.Keys, Is.EquivalentTo(Values("3c")));
    }

    [Test]
    public async Task StartAsync_DownloadsStatusList_WhenEmbeddedResourceIsNotFound()
    {
        WebAuthnOptions.AttestationStatements.AndroidKey.StatusList.EmbeddedStatusList = new(EmbeddedStatusListAssembly, "WebAuthn.Net.Missing.status.json");
        HttpClient.EnqueueSuccess(StatusListWithOneEntry);

        await StartServiceAsync();

        Assert.Multiple(() =>
        {
            Assert.That(HttpClient.Calls, Is.EqualTo(1));
            Assert.That(Storage.StatusList?.Entries.Keys, Is.EquivalentTo(Values("3c")));
            Assert.That(Counters.EmbeddedFailures, Is.EqualTo(Values(AndroidKeyAttestationStatusListFailures.ResourceNotFound)));
            Assert.That(Warnings(), Has.Exactly(1).Contains("doesn't contain the manifest resource 'WebAuthn.Net.Missing.status.json'").And.Contains(EmbeddedStatusListResourceName));
        });
    }

    [Test]
    public async Task StartAsync_DownloadsStatusList_WhenEmbeddedStatusListIsMalformed()
    {
        WebAuthnOptions.AttestationStatements.AndroidKey.StatusList.EmbeddedStatusList = new(EmbeddedStatusListAssembly, "WebAuthn.Net.DSL.Fakes.FakeResources.blob.jwt");
        HttpClient.EnqueueSuccess(StatusListWithOneEntry);

        await StartServiceAsync();

        Assert.Multiple(() =>
        {
            Assert.That(HttpClient.Calls, Is.EqualTo(1));
            Assert.That(Storage.StatusList?.Entries.Keys, Is.EquivalentTo(Values("3c")));
            Assert.That(Counters.EmbeddedFailures, Is.EqualTo(Values(AndroidKeyAttestationStatusListFailures.ListInvalid)));
            Assert.That(Warnings(), Has.One.StartsWith("The status list of the Android attestation keys embedded in the application (the manifest resource 'WebAuthn.Net.DSL.Fakes.FakeResources.blob.jwt'").And.EndsWith("is malformed"));
        });
    }

    [Test]
    public async Task DownloadStatusListAsync_CountsTimeout()
    {
        HttpClient.EnqueueFailure(new TimeoutException("The download timed out"));

        await StartServiceAsync();

        Assert.Multiple(() =>
        {
            Assert.That(Counters.DownloadFailures, Is.EqualTo(Values(AndroidKeyAttestationStatusListFailures.Timeout)));
            Assert.That(Warnings(), Is.EqualTo(Values("Failed to download the status list of the Android attestation keys")));
        });
    }

    [Test]
    public async Task DownloadStatusListAsync_KeepsStatusListInUse_WhenDownloadedStatusListIsMalformed()
    {
        HttpClient.EnqueueSuccess(StatusListWithTwoEntries);
        await StartServiceAsync();
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(TimeSpan.FromDays(1)));

        HttpClient.EnqueueSuccess("""{"entries":[]}""");
        Service.ReleaseDelay();

        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(TimeSpan.FromMinutes(1)));
        Assert.Multiple(() =>
        {
            Assert.That(Storage.StatusList?.Entries.Keys, Is.EquivalentTo(Values("1a", "2b")));
            Assert.That(Counters.DownloadFailures, Is.EqualTo(Values(AndroidKeyAttestationStatusListFailures.ListInvalid)));
            Assert.That(Warnings(), Has.One.EqualTo("The downloaded status list of the Android attestation keys is malformed"));
        });
    }

    [Test]
    public async Task DownloadStatusListAsync_LogsAndCountsUnexpectedException_AndRetries()
    {
        HttpClient.EnqueueFailure(new InvalidOperationException("The circuit is open"));

        await StartServiceAsync();

        var errors = Logger.Entries.Where(static x => x.Level == LogLevel.Error).ToArray();
        Assert.Multiple(() =>
        {
            Assert.That(errors.Select(static x => x.Message), Is.EqualTo(Values("Failed to download the status list of the Android attestation keys because of an exception")));
            Assert.That(errors.Single().Exception, Is.InstanceOf<InvalidOperationException>());
            Assert.That(Counters.IngestExceptions, Is.EqualTo(Values(AndroidKeyAttestationStatusListSources.Download)));
        });
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(TimeSpan.FromMinutes(1)));
    }

    [Test]
    public async Task GetNextDelay_UsesDefaultInterval_WhenConfiguredIntervalIsNotPositive()
    {
        WebAuthnOptions.AttestationStatements.AndroidKey.StatusList.IngestInterval = TimeSpan.Zero;
        HttpClient.EnqueueSuccess(StatusListWithOneEntry);

        await StartServiceAsync();

        Assert.Multiple(() =>
        {
            Assert.That(
                Logger.Entries.Where(static x => x.Level == LogLevel.Error).Select(static x => x.Message),
                Is.EqualTo(Values("The IngestInterval of 00:00:00 is not a positive interval, so the default interval of 1.00:00:00 is used instead")));
        });
        Assert.That(await Service.WaitForDelayAsync(), Is.EqualTo(TimeSpan.FromDays(1)));
    }

    [Test]
    public void DefaultOptions_DownloadFromGoogle_RefreshEveryDay_AndRetryEveryMinute()
    {
        var options = new WebAuthnOptions().AttestationStatements.AndroidKey.StatusList;

        Assert.Multiple(() =>
        {
            Assert.That(options.DownloadUri, Is.EqualTo(new Uri("https://android.googleapis.com/attestation/status")));
            Assert.That(options.MaxResponseSizeInBytes, Is.EqualTo(16L * 1024 * 1024));
            Assert.That(options.DownloadTimeout, Is.EqualTo(TimeSpan.FromMinutes(1)));
            Assert.That(options.IngestInterval, Is.EqualTo(TimeSpan.FromDays(1)));
            Assert.That(options.RetryInterval, Is.EqualTo(TimeSpan.FromMinutes(1)));
            Assert.That(options.EmbeddedStatusList, Is.Null);
        });
    }

    [Test]
    public async Task AddWebAuthnCore_RegistersStatusListServices_ThatContainerCanConstruct()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddWebAuthnCore<FakeWebAuthnContext>(static options => options.AttestationStatements.AndroidKey.StatusList.RetryInterval = TimeSpan.FromSeconds(30))
            .AddDefaultFidoMetadataStorage();
        // registered after AddWebAuthnCore, so that it replaces the typed HttpClient and the service doesn't go to the network
        services.AddSingleton<IAndroidKeyAttestationStatusHttpClient>(HttpClient);
        await using var serviceProvider = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = false,
            ValidateScopes = true
        });
        HttpClient.EnqueueSuccess(StatusListWithOneEntry);

        var backgroundService = serviceProvider.GetServices<IHostedService>().OfType<AndroidKeyAttestationStatusIngestBackgroundService>().Single();
        var storage = serviceProvider.GetRequiredService<IAndroidKeyAttestationStatusStorage>();
        var verifier = serviceProvider.GetRequiredService<IAndroidKeyAttestationStatementVerifier<FakeWebAuthnContext>>();
        await backgroundService.StartAsync(CancellationToken.None).WaitAsync(TestTimeout);
        await backgroundService.StopAsync(CancellationToken.None).WaitAsync(TestTimeout);

        Assert.Multiple(() =>
        {
            Assert.That(storage, Is.InstanceOf<DefaultInMemoryAndroidKeyAttestationStatusStorage>());
            Assert.That(verifier, Is.InstanceOf<DefaultAndroidKeyAttestationStatementVerifier<FakeWebAuthnContext>>());
            Assert.That(serviceProvider.GetRequiredService<IAndroidKeyAttestationStatusCounters>(), Is.Not.Null);
            Assert.That(serviceProvider.GetRequiredService<IOptionsMonitor<WebAuthnOptions>>().CurrentValue.AttestationStatements.AndroidKey.StatusList.RetryInterval, Is.EqualTo(TimeSpan.FromSeconds(30)));
            Assert.That(HttpClient.Calls, Is.EqualTo(1));
        });
        Assert.That((await storage.GetAsync(CancellationToken.None))?.Entries.Keys, Is.EquivalentTo(Values("3c")));
    }

    private Task StartServiceAsync()
    {
        return Service.StartAsync(CancellationToken.None).WaitAsync(TestTimeout);
    }

    private static string[] Values(params string[] values)
    {
        return values;
    }

    private string[] Information()
    {
        return Logger.Entries.Where(static x => x.Level == LogLevel.Information).Select(static x => x.Message).ToArray();
    }

    private string[] Warnings()
    {
        return Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message).ToArray();
    }

    private sealed class OptionsMonitorStub : IOptionsMonitor<WebAuthnOptions>
    {
        public OptionsMonitorStub(WebAuthnOptions options)
        {
            CurrentValue = options;
        }

        public WebAuthnOptions CurrentValue { get; }

        public WebAuthnOptions Get(string? name)
        {
            return CurrentValue;
        }

        public IDisposable? OnChange(Action<WebAuthnOptions, string?> listener)
        {
            return null;
        }
    }

    /// <summary>
    ///     An HTTP client that returns the configured responses in order. A response can be held back until it is released, so that a test can observe the state before it.
    /// </summary>
    private sealed class FakeStatusHttpClient : IAndroidKeyAttestationStatusHttpClient
    {
        private readonly ConcurrentQueue<(Func<string> Response, TaskCompletionSource? Gate)> _responses = new();
        private int _calls;

        public int Calls => _calls;

        public TaskCompletionSource? EnqueueSuccess(string json, bool held = false)
        {
            var gate = held ? new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously) : null;
            _responses.Enqueue((() => json, gate));
            return gate;
        }

        public void EnqueueFailure(Exception exception)
        {
            _responses.Enqueue((() => throw exception, null));
        }

        public async Task<string> DownloadStatusListAsync(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            if (!_responses.TryDequeue(out var response))
            {
                throw new InvalidOperationException("No response is configured");
            }

            if (response.Gate is not null)
            {
                await response.Gate.Task.WaitAsync(cancellationToken);
            }

            return response.Response();
        }
    }

    /// <summary>
    ///     The background service whose delays are reported to the test and end only when the test releases them (a zero delay ends at once).
    /// </summary>
    private sealed class GatedBackgroundService : AndroidKeyAttestationStatusIngestBackgroundService
    {
        private readonly Channel<TimeSpan> _delays = Channel.CreateUnbounded<TimeSpan>();
        private readonly Channel<bool> _releases = Channel.CreateUnbounded<bool>();

        public GatedBackgroundService(
            IOptionsMonitor<WebAuthnOptions> options,
            IAndroidKeyAttestationStatusHttpClient httpClient,
            IAndroidKeyAttestationStatusDecoder decoder,
            IAndroidKeyAttestationStatusStorage storage,
            ITimeProvider timeProvider,
            IAndroidKeyAttestationStatusCounters counters,
            ILogger<AndroidKeyAttestationStatusIngestBackgroundService> logger)
            : base(options, httpClient, decoder, storage, timeProvider, counters, logger)
        {
        }

        public async Task<TimeSpan> WaitForDelayAsync()
        {
            using var timeout = new CancellationTokenSource(TestTimeout);
            return await _delays.Reader.ReadAsync(timeout.Token);
        }

        public void ReleaseDelay()
        {
            _releases.Writer.TryWrite(true);
        }

        protected override async Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            _delays.Writer.TryWrite(delay);
            if (delay > TimeSpan.Zero)
            {
                await _releases.Reader.ReadAsync(cancellationToken);
            }
        }
    }
}
