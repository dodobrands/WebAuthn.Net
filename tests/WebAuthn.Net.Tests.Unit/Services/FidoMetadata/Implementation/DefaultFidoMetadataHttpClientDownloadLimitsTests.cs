using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataHttpClient;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

public class DefaultFidoMetadataHttpClientDownloadLimitsTests
{
    private const long MaxResponseSize = 1024;
    private const long OversizedContentLength = 2L * 1024 * 1024 * 1024;
    private static readonly TimeSpan LongDownloadTimeout = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan ShortDownloadTimeout = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan TestTimeout = TimeSpan.FromSeconds(30);

    private ConfigurationManager ConfigurationManager { get; set; } = null!;
    private OptionsMonitor<WebAuthnOptions> Options { get; set; } = null!;
    private FakeLogger<DefaultFidoMetadataHttpClient> Logger { get; set; } = null!;
    private CancellationTokenSource ReleaseCts { get; set; } = null!;
    private FakeResponseHandler Handler { get; set; } = null!;
    private HttpClient HttpClient { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        ConfigurationManager = new();
        var webAuthnOptions = FakeWebAuthnOptionsFactory.Create(ConfigurationManager);
        var optionsCache = new OptionsCache<WebAuthnOptions>();
        optionsCache.TryAdd(string.Empty, webAuthnOptions);
        Options = new(
            new OptionsFactory<WebAuthnOptions>(
                new List<IConfigureOptions<WebAuthnOptions>>(),
                new List<IPostConfigureOptions<WebAuthnOptions>>()),
            new List<IOptionsChangeTokenSource<WebAuthnOptions>>
            {
                new ConfigurationChangeTokenSource<WebAuthnOptions>(ConfigurationManager)
            },
            optionsCache);
        Logger = new();
        ReleaseCts = new();
        Handler = new();
        HttpClient = new(Handler, false);
    }

    [TearDown]
    public void TearDownServices()
    {
        // Releases the bodies that hang (simulating a connection that never delivers the data) if a test left them pending.
        ReleaseCts.Cancel();
        HttpClient.Dispose();
        Handler.Dispose();
        ReleaseCts.Dispose();
        Options.Dispose();
        ConfigurationManager.Dispose();
    }

    [Test]
    public async Task DefaultFidoMetadataHttpClient_DownloadMetadata_WhenBodyIsWithinLimit_ReturnsTrimmedBody()
    {
        Handler.ContentFactory = static () => new FakeStreamingContent(Encoding.UTF8.GetBytes("  a.b.c \r\n"));
        var client = CreateClient();

        var result = await client.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result, Is.EqualTo("a.b.c"));
        Assert.That(Logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
    }

    [Test]
    public async Task DefaultFidoMetadataHttpClient_DownloadMetadata_WhenBodyStartsWithByteOrderMark_StripsIt()
    {
        Handler.ContentFactory = static () => new FakeStreamingContent(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes("a.b.c")).ToArray());
        var client = CreateClient();

        var result = await client.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result, Is.EqualTo("a.b.c"));
    }

    [Test]
    public async Task DefaultFidoMetadataHttpClient_DownloadMetadata_WhenDeclaredContentLengthExceedsLimit_ThrowsWithoutReadingBody()
    {
        Handler.ContentFactory = static () => new FakeStreamingContent(Encoding.UTF8.GetBytes("a.b.c"), OversizedContentLength);
        var client = CreateClient();

        var exception = await Assert.ThrowsAsync<HttpRequestException>(async () => await client.DownloadMetadataAsync(CancellationToken.None));

        Assert.That(exception.Message, Does.Contain("exceeds the maximum allowed size of 1024 bytes"));
        Assert.That(Handler.LastContent?.BodyRequested, Is.False);
        var warnings = Logger.Entries.Where(static x => x.Level == LogLevel.Warning).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(1));
        Assert.That(warnings[0].Message, Does.Contain("declares a body of 2147483648 bytes"));
    }

    [Test]
    public async Task DefaultFidoMetadataHttpClient_DownloadMetadata_WhenBodyExceedsLimitWithoutContentLength_Throws()
    {
        // Without 'Content-Length' (for example, chunked transfer encoding) the limit can be enforced only while reading the body.
        Handler.ContentFactory = static () => new FakeStreamingContent(new byte[2048]);
        var client = CreateClient();

        var exception = await Assert.ThrowsAsync<HttpRequestException>(async () => await client.DownloadMetadataAsync(CancellationToken.None));

        Assert.That(exception.Message, Does.Contain("exceeds the maximum allowed size of 1024 bytes"));
        var warnings = Logger.Entries.Where(static x => x.Level == LogLevel.Warning).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(1));
        Assert.That(warnings[0].Message, Does.Contain("the response body exceeds the maximum allowed size of 1024 bytes"));
    }

    [Test]
    public async Task DefaultFidoMetadataHttpClient_DownloadMetadata_WhenBodyExceedsLimitDespiteSmallerContentLength_Throws()
    {
        // The 'Content-Length' header can't be trusted: the body is longer than declared.
        Handler.ContentFactory = static () => new FakeStreamingContent(new byte[2048], 10);
        var client = CreateClient();

        var exception = await Assert.ThrowsAsync<HttpRequestException>(async () => await client.DownloadMetadataAsync(CancellationToken.None));

        Assert.That(exception.Message, Does.Contain("exceeds the maximum allowed size of 1024 bytes"));
        var warnings = Logger.Entries.Where(static x => x.Level == LogLevel.Warning).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(1));
        Assert.That(warnings[0].Message, Does.Contain("the 'Content-Length' header of the response: 10"));
    }

    [Test]
    public async Task DefaultFidoMetadataHttpClient_DownloadMetadata_WhenBodyIsNotReceivedWithinDownloadTimeout_ThrowsTimeoutException()
    {
        // HttpClient.Timeout covers only the response headers when the body is read as a stream, so a body that never arrives must be limited by the client itself.
        var releaseToken = ReleaseCts.Token;
        Handler.ContentFactory = () => new FakeStreamingContent(Encoding.UTF8.GetBytes("a.b.c"), null, true, releaseToken);
        var client = CreateClient(ShortDownloadTimeout);

        var downloadTask = client.DownloadMetadataAsync(CancellationToken.None);
        var completedTask = await Task.WhenAny(downloadTask, Task.Delay(TestTimeout, releaseToken));

        Assert.That(completedTask, Is.SameAs(downloadTask), "The download didn't complete within the test timeout");
        var exception = await Assert.ThrowsAsync<TimeoutException>(async () => await downloadTask);
        Assert.That(exception.InnerException, Is.InstanceOf<OperationCanceledException>());
        var warnings = Logger.Entries.Where(static x => x.Level == LogLevel.Warning).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(1));
        Assert.That(warnings[0].Message, Does.Contain("download timeout of 00:00:00.5000000"));
    }

    [Test]
    public async Task DefaultFidoMetadataHttpClient_DownloadMetadata_WhenCallerCancels_PropagatesCancellationWithoutWarning()
    {
        var releaseToken = ReleaseCts.Token;
        Handler.ContentFactory = () => new FakeStreamingContent(Encoding.UTF8.GetBytes("a.b.c"), null, true, releaseToken);
        var client = CreateClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        var downloadTask = client.DownloadMetadataAsync(cts.Token);
        var completedTask = await Task.WhenAny(downloadTask, Task.Delay(TestTimeout, releaseToken));

        Assert.That(completedTask, Is.SameAs(downloadTask), "The download didn't complete within the test timeout");
        var exception = await Assert.CatchAsync<OperationCanceledException>(async () => await downloadTask);
        Assert.That(exception, Is.Not.InstanceOf<TimeoutException>());
        Assert.That(Logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
    }

    [Test]
    public async Task DefaultFidoMetadataHttpClient_DownloadMetadata_WhenRegisteredAsTypedHttpClient_UsesLoggerFromDependencyInjection()
    {
        // The typed HttpClient factory must pick the constructor with the logger (there are two constructors), otherwise the aborted downloads would be logged nowhere.
        var services = new ServiceCollection();
        services
            .AddHttpClient<IFidoMetadataHttpClient, DefaultFidoMetadataHttpClient>()
            .ConfigurePrimaryHttpMessageHandler(static () => new FakeResponseHandler
            {
                ContentFactory = static () => new FakeStreamingContent(Encoding.UTF8.GetBytes("a.b.c"), OversizedContentLength)
            });
        services.AddSingleton<IOptionsMonitor<WebAuthnOptions>>(Options);
        services.AddSingleton<ILogger<DefaultFidoMetadataHttpClient>>(Logger);
        await using var serviceProvider = services.BuildServiceProvider();
        var client = serviceProvider.GetRequiredService<IFidoMetadataHttpClient>();

        await Assert.ThrowsAsync<HttpRequestException>(async () => await client.DownloadMetadataAsync(CancellationToken.None));

        Assert.That(client, Is.InstanceOf<DefaultFidoMetadataHttpClient>());
        var warnings = Logger.Entries.Where(static x => x.Level == LogLevel.Warning).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(1));
        Assert.That(warnings[0].Message, Does.Contain("declares a body of 2147483648 bytes").And.Contain("67108864 bytes"));
    }

    private DefaultFidoMetadataHttpClient CreateClient(TimeSpan? downloadTimeout = null)
    {
        var fidoMetadataOptions = Options.CurrentValue.FidoMetadata;
        fidoMetadataOptions.MaxResponseSizeInBytes = MaxResponseSize;
        fidoMetadataOptions.DownloadTimeout = downloadTimeout ?? LongDownloadTimeout;
        return new(HttpClient, Options, Logger);
    }

    private sealed class FakeResponseHandler : HttpMessageHandler
    {
        public Func<FakeStreamingContent>? ContentFactory { get; set; }

        public FakeStreamingContent? LastContent { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var contentFactory = ContentFactory ?? throw new InvalidOperationException("The content of the response is not configured");
            var content = contentFactory();
            LastContent = content;
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = content
            };
            return Task.FromResult(response);
        }
    }

    /// <summary>
    ///     Content that, like the content of a real network response, exposes its body as a stream instead of buffering it,
    ///     optionally declares an arbitrary 'Content-Length' and optionally never delivers the body (until the release token is cancelled).
    /// </summary>
    private sealed class FakeStreamingContent : HttpContent
    {
        private readonly byte[] _body;
        private readonly long? _declaredLength;
        private readonly bool _hang;
        private readonly CancellationToken _releaseToken;

        public FakeStreamingContent(byte[] body, long? declaredLength = null, bool hang = false, CancellationToken releaseToken = default)
        {
            _body = body;
            _declaredLength = declaredLength;
            _hang = hang;
            _releaseToken = releaseToken;
        }

        public bool BodyRequested { get; private set; }

        protected override Task<Stream> CreateContentReadStreamAsync()
        {
            BodyRequested = true;
            return Task.FromResult<Stream>(new FakeBodyStream(_body, _hang, _releaseToken));
        }

        protected override Task<Stream> CreateContentReadStreamAsync(CancellationToken cancellationToken)
        {
            return CreateContentReadStreamAsync();
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            BodyRequested = true;
            return stream.WriteAsync(_body, 0, _body.Length);
        }

        protected override bool TryComputeLength(out long length)
        {
            if (_declaredLength is null)
            {
                length = 0;
                return false;
            }

            length = _declaredLength.Value;
            return true;
        }
    }

    private sealed class FakeBodyStream : Stream
    {
        private readonly byte[] _body;
        private readonly bool _hang;
        private readonly CancellationToken _releaseToken;
        private int _position;

        public FakeBodyStream(byte[] body, bool hang, CancellationToken releaseToken)
        {
            _body = body;
            _hang = hang;
            _releaseToken = releaseToken;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_hang)
            {
                // Simulates a connection that stays open but never delivers the body; only the cancellation can end the wait.
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _releaseToken);
                await Task.Delay(Timeout.Infinite, linkedCts.Token);
            }

            return Read(buffer.Span);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        }

        public override int Read(Span<byte> buffer)
        {
            var bytesToCopy = Math.Min(buffer.Length, _body.Length - _position);
            _body.AsSpan(_position, bytesToCopy).CopyTo(buffer);
            _position += bytesToCopy;
            return bytesToCopy;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return Read(buffer.AsSpan(offset, count));
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }
}
