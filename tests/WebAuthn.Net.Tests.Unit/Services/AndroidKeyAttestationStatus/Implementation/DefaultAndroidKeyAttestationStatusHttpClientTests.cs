using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusHttpClient;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation;

public class DefaultAndroidKeyAttestationStatusHttpClientTests
{
    private const long MaxResponseSize = 1024;
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(30);

    private WebAuthnOptions WebAuthnOptions { get; set; } = null!;
    private FakeLogger<DefaultAndroidKeyAttestationStatusHttpClient> Logger { get; set; } = null!;
    private FakeResponseHandler Handler { get; set; } = null!;
    private HttpClient HttpClient { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        WebAuthnOptions = new();
        WebAuthnOptions.AttestationStatements.AndroidKey.StatusList.MaxResponseSizeInBytes = MaxResponseSize;
        Logger = new();
        Handler = new();
        HttpClient = new(Handler, false);
    }

    [TearDown]
    public void TearDownServices()
    {
        HttpClient.Dispose();
        Handler.Dispose();
    }

    [Test]
    public async Task DownloadStatusListAsync_RequestsDownloadUri_AndReturnsBody()
    {
        Handler.Body = Encoding.UTF8.GetBytes("""{"entries":{}}""");

        var result = await CreateClient().DownloadStatusListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.EqualTo("""{"entries":{}}"""));
            Assert.That(Handler.RequestedUri, Is.EqualTo(new Uri("https://android.googleapis.com/attestation/status")));
            Assert.That(Logger.Entries, Is.Empty);
        });
    }

    [Test]
    public async Task DownloadStatusListAsync_RequestsConfiguredDownloadUri()
    {
        Handler.Body = Encoding.UTF8.GetBytes("""{"entries":{}}""");
        WebAuthnOptions.AttestationStatements.AndroidKey.StatusList.DownloadUri = new("https://mirror.example.com/status.json");

        await CreateClient().DownloadStatusListAsync(CancellationToken.None);

        Assert.That(Handler.RequestedUri, Is.EqualTo(new Uri("https://mirror.example.com/status.json")));
    }

    [Test]
    public async Task DownloadStatusListAsync_StripsByteOrderMark()
    {
        Handler.Body = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes("""{"entries":{}}""")).ToArray();

        var result = await CreateClient().DownloadStatusListAsync(CancellationToken.None);

        Assert.That(result, Is.EqualTo("""{"entries":{}}"""));
    }

    [Test]
    public async Task DownloadStatusListAsync_Throws_WhenResponseHasUnsuccessfulStatusCode()
    {
        Handler.StatusCode = HttpStatusCode.ServiceUnavailable;

        await Assert.ThrowsAsync<HttpRequestException>(async () => await CreateClient().DownloadStatusListAsync(CancellationToken.None));
    }

    [Test]
    public async Task DownloadStatusListAsync_ThrowsWithoutReadingBody_WhenDeclaredContentLengthExceedsLimit()
    {
        Handler.Body = new byte[16];
        Handler.DeclaredLength = MaxResponseSize + 1;

        var exception = await Assert.ThrowsAsync<HttpRequestException>(async () => await CreateClient().DownloadStatusListAsync(CancellationToken.None));

        Assert.Multiple(() =>
        {
            Assert.That(exception!.Message, Does.Contain("declares a body of 1025 bytes, which exceeds the maximum allowed size of 1024 bytes"));
            Assert.That(Handler.BodyRequested, Is.False);
            Assert.That(
                Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.One.EqualTo("The download of the status list of the Android attestation keys was aborted because the response declares a body of 1025 bytes, which exceeds the maximum allowed size of 1024 bytes"));
        });
    }

    [TestCase(null)]
    [TestCase(10L)]
    public async Task DownloadStatusListAsync_Throws_WhenBodyExceedsLimit(long? declaredLength)
    {
        Handler.Body = new byte[MaxResponseSize + 1];
        Handler.DeclaredLength = declaredLength;

        var exception = await Assert.ThrowsAsync<HttpRequestException>(async () => await CreateClient().DownloadStatusListAsync(CancellationToken.None));

        Assert.Multiple(() =>
        {
            Assert.That(exception!.Message, Does.Contain("exceeds the maximum allowed size of 1024 bytes"));
            Assert.That(
                Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.One.Contains("the response body exceeds the maximum allowed size of 1024 bytes"));
        });
    }

    [Test]
    public async Task DownloadStatusListAsync_ThrowsTimeoutException_WhenDownloadIsNotCompletedWithinDownloadTimeout()
    {
        Handler.Hang = true;
        WebAuthnOptions.AttestationStatements.AndroidKey.StatusList.DownloadTimeout = TimeSpan.FromMilliseconds(200);

        var downloadTask = CreateClient().DownloadStatusListAsync(CancellationToken.None);
        var completedTask = await Task.WhenAny(downloadTask, Task.Delay(TestTimeout));

        Assert.That(completedTask, Is.SameAs(downloadTask), "The download didn't complete within the test timeout");
        var exception = await Assert.ThrowsAsync<TimeoutException>(async () => await downloadTask);
        Assert.Multiple(() =>
        {
            Assert.That(exception!.InnerException, Is.InstanceOf<OperationCanceledException>());
            Assert.That(
                Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.One.Contains("wasn't completed within the download timeout of 00:00:00.2000000"));
        });
    }

    [Test]
    public async Task DownloadStatusListAsync_PropagatesCancellationWithoutWarning_WhenCallerCancels()
    {
        Handler.Hang = true;
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        var downloadTask = CreateClient().DownloadStatusListAsync(cts.Token);
        var completedTask = await Task.WhenAny(downloadTask, Task.Delay(TestTimeout));

        Assert.That(completedTask, Is.SameAs(downloadTask), "The download didn't complete within the test timeout");
        var exception = await Assert.CatchAsync<OperationCanceledException>(async () => await downloadTask);
        Assert.Multiple(() =>
        {
            Assert.That(exception, Is.Not.InstanceOf<TimeoutException>());
            Assert.That(Logger.Entries, Is.Empty);
        });
    }

    [Test]
    public async Task DownloadStatusListAsync_UsesConfiguredHttpClient_WhenRegisteredAsTypedHttpClient()
    {
        var services = new ServiceCollection();
        services
            .AddHttpClient<IAndroidKeyAttestationStatusHttpClient, DefaultAndroidKeyAttestationStatusHttpClient>()
            .ConfigurePrimaryHttpMessageHandler(static () => new FakeResponseHandler { Body = Encoding.UTF8.GetBytes("""{"entries":{}}""") });
        services.AddSingleton<IOptionsMonitor<WebAuthnOptions>>(new OptionsMonitorStub(WebAuthnOptions));
        services.AddSingleton<ILogger<DefaultAndroidKeyAttestationStatusHttpClient>>(Logger);
        await using var serviceProvider = services.BuildServiceProvider();
        var client = serviceProvider.GetRequiredService<IAndroidKeyAttestationStatusHttpClient>();

        var result = await client.DownloadStatusListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(client, Is.InstanceOf<DefaultAndroidKeyAttestationStatusHttpClient>());
            Assert.That(result, Is.EqualTo("""{"entries":{}}"""));
        });
    }

    private DefaultAndroidKeyAttestationStatusHttpClient CreateClient()
    {
        return new(HttpClient, new OptionsMonitorStub(WebAuthnOptions), Logger);
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

    private sealed class FakeResponseHandler : HttpMessageHandler
    {
        public HttpStatusCode StatusCode { get; set; } = HttpStatusCode.OK;

        public byte[] Body { get; set; } = Array.Empty<byte>();

        // null: the response doesn't declare the length of its body
        public long? DeclaredLength { get; set; }

        // the response headers never arrive (until the request is cancelled)
        public bool Hang { get; set; }

        public Uri? RequestedUri { get; private set; }

        public bool BodyRequested => LastContent?.BodyRequested ?? false;

        private FakeContent? LastContent { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestedUri = request.RequestUri;
            if (Hang)
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }

            LastContent = new(Body, DeclaredLength);
            return new(StatusCode)
            {
                Content = LastContent
            };
        }
    }

    private sealed class FakeContent : HttpContent
    {
        private readonly byte[] _body;
        private readonly long? _declaredLength;

        public FakeContent(byte[] body, long? declaredLength)
        {
            _body = body;
            _declaredLength = declaredLength;
        }

        public bool BodyRequested { get; private set; }

        protected override Task<Stream> CreateContentReadStreamAsync()
        {
            BodyRequested = true;
            return Task.FromResult<Stream>(new MemoryStream(_body, false));
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            BodyRequested = true;
            return stream.WriteAsync(_body, 0, _body.Length);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _declaredLength ?? 0;
            return _declaredLength.HasValue;
        }
    }
}
