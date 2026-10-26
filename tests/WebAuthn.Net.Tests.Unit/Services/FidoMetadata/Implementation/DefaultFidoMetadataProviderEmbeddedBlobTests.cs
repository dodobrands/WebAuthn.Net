using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.DSL;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider.Constants;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Serialization.Json.Implementation;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

// The blob embedded in the application is the genuine blob (no: 291), embedded in the test assembly as a manifest resource.
// It is validated like a downloaded blob, except that the validity period and the revocation status of its signing certificates are not checked:
// the blobs are signed with short-lived certificates, and the embedded blob has to work regardless of the time and of the availability of the network.
public class DefaultFidoMetadataProviderEmbeddedBlobTests
{
    private const string BlobResourceName = "WebAuthn.Net.DSL.Fakes.FakeResources.blob.jwt";
    private const long BlobNo = 291;

    private static readonly DateTimeOffset CurrentDate = DateTimeOffset.Parse("2026-10-17T17:20:02.0000000+00:00", CultureInfo.InvariantCulture);

    // The signing certificate of the blob (no: 291) expires on 2027-03-08.
    private static readonly DateTimeOffset AfterSigningCertificateExpiration = DateTimeOffset.Parse("2035-01-01T00:00:00.0000000+00:00", CultureInfo.InvariantCulture);

    private static readonly Assembly TestAssembly = typeof(DefaultFidoMetadataProviderEmbeddedBlobTests).Assembly;

    private OptionsMonitor<WebAuthnOptions> Options { get; set; } = null!;
    private WebAuthnOptions WebAuthnOptions { get; set; } = null!;
    private ConfigurationManager ConfigurationManager { get; set; } = null!;
    private FakeFidoMetadataCounters Counters { get; set; } = null!;
    private FakeLogger<DefaultFidoMetadataProvider> Logger { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        ConfigurationManager = new();
        WebAuthnOptions = FakeWebAuthnOptionsFactory.Create(ConfigurationManager);
        var optionsCache = new OptionsCache<WebAuthnOptions>();
        optionsCache.TryAdd(string.Empty, WebAuthnOptions);
        Options = new(
            new OptionsFactory<WebAuthnOptions>(
                new List<IConfigureOptions<WebAuthnOptions>>(),
                new List<IPostConfigureOptions<WebAuthnOptions>>()),
            new List<IOptionsChangeTokenSource<WebAuthnOptions>>
            {
                new ConfigurationChangeTokenSource<WebAuthnOptions>(ConfigurationManager)
            },
            optionsCache);
        Counters = new();
        Logger = new();
    }

    [TearDown]
    public void TearDownServices()
    {
        Options.Dispose();
        ConfigurationManager.Dispose();
    }

    [Test]
    public async Task LoadEmbeddedMetadataAsync_WhenResourceContainsGenuineBlob_ReturnsPayloadWithoutNetwork()
    {
        // The HTTP client throws: the embedded blob must not be downloaded, and its chain must be validated without the network.
        var provider = CreateProvider(CurrentDate);

        var result = await provider.LoadEmbeddedMetadataAsync(TestAssembly, BlobResourceName, CancellationToken.None);

        Assert.That(result.HasError, Is.False);
        Assert.That(result.Ok!.No, Is.EqualTo(BlobNo));
        Assert.That(result.Ok.Entries, Is.Not.Empty);
        Assert.That(Logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
        Assert.Multiple(() =>
        {
            Assert.That(Counters.EmbeddedLoadStarts, Is.EqualTo(1));
            Assert.That(Counters.SuccessfulEmbeddedLoadEnds, Is.EqualTo(1));
            Assert.That(Counters.FailedEmbeddedLoadEnds, Is.Zero);
            Assert.That(Counters.EmbeddedLoadFailures, Is.Empty);
            Assert.That(Counters.DownloadStarts, Is.Zero, "the embedded blob is not a download");
        });
    }

    [Test]
    public async Task LoadEmbeddedMetadataAsync_WhenSigningCertificatesHaveExpired_ReturnsPayload()
    {
        // Years after the signing certificate has expired, the embedded blob is still accepted: both the checks of the provider (at the time of ITimeProvider)
        // and the chain engine (at the verification time of the chain) ignore the validity period. A downloaded blob would be rejected at that time.
        WebAuthnOptions.X509ChainValidation.OnValidateEmbeddedFidoMetadataBlobJwtChain = static chain =>
        {
            new X509ChainValidationOptions().OnValidateEmbeddedFidoMetadataBlobJwtChain(chain);
            chain.ChainPolicy.VerificationTime = AfterSigningCertificateExpiration.UtcDateTime;
        };
        var provider = CreateProvider(AfterSigningCertificateExpiration);

        var result = await provider.LoadEmbeddedMetadataAsync(TestAssembly, BlobResourceName, CancellationToken.None);

        Assert.That(result.HasError, Is.False);
        Assert.That(result.Ok!.No, Is.EqualTo(BlobNo));
        Assert.That(Logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
    }

    [Test]
    public async Task DownloadMetadataAsync_WhenSigningCertificatesHaveExpired_ReturnsFail()
    {
        // The counterpart of the test above: the same blob downloaded from the FIDO Metadata Service after its signing certificate has expired is rejected.
        var provider = CreateProvider(AfterSigningCertificateExpiration, new StaticFidoMetadataHttpClient(GetGenuineBlob()));

        var result = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        Assert.That(Counters.DownloadFailures, Is.EqualTo(new[] { FidoMetadataDownloadFailures.X5CInvalid }));
    }

    [Test]
    public async Task LoadEmbeddedMetadataAsync_UsesEmbeddedBlobChainPolicy()
    {
        // A custom policy that requires the validity period at a time after the expiration of the signing certificate rejects the blob,
        // so the chain of the embedded blob is validated according to OnValidateEmbeddedFidoMetadataBlobJwtChain (and not according to the policy of the downloaded blobs).
        WebAuthnOptions.X509ChainValidation.OnValidateEmbeddedFidoMetadataBlobJwtChain = static chain =>
        {
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.VerificationTime = AfterSigningCertificateExpiration.UtcDateTime;
        };
        var provider = CreateProvider(CurrentDate);

        var result = await provider.LoadEmbeddedMetadataAsync(TestAssembly, BlobResourceName, CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        AssertEmbeddedFailureCounted(FidoMetadataEmbeddedBlobFailures.ChainInvalid);
        var warnings = Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(2));
        Assert.That(warnings[0], Does.Contain("signing certificate chain of the FIDO Metadata Service blob is invalid"));
        Assert.That(warnings[1], Does.Contain("embedded in the application").And.Contain(BlobResourceName).And.Contain("rejected: chain_invalid"));
    }

    [Test]
    public async Task LoadEmbeddedMetadataAsync_DoesNotPerformAdditionalChainValidation()
    {
        // The additional validation (for example, a revocation check against CRLs) needs the network, so it applies only to the downloaded blobs.
        var provider = new RejectingChainFidoMetadataProvider(
            Options,
            new DefaultSafeJsonSerializer(NullLogger<DefaultSafeJsonSerializer>.Instance),
            new StaticFidoMetadataHttpClient(GetGenuineBlob()),
            new FakeTimeProvider(CurrentDate),
            Counters,
            Logger);

        var embeddedResult = await provider.LoadEmbeddedMetadataAsync(TestAssembly, BlobResourceName, CancellationToken.None);
        var downloadResult = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(embeddedResult.HasError, Is.False);
        Assert.That(downloadResult.HasError, Is.True);
        Assert.That(provider.Validations, Is.EqualTo(1));
        Assert.That(Counters.DownloadFailures, Is.EqualTo(new[] { FidoMetadataDownloadFailures.ChainRejected }));
    }

    [Test]
    public async Task LoadEmbeddedMetadataAsync_WhenResourceIsMissing_ReturnsFailAndWarnsWithResourceNames()
    {
        var provider = CreateProvider(CurrentDate);

        var result = await provider.LoadEmbeddedMetadataAsync(TestAssembly, "WebAuthn.Net.blob.jwt", CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        AssertEmbeddedFailureCounted(FidoMetadataEmbeddedBlobFailures.ResourceNotFound);
        var warnings = Logger.Entries.Where(static x => x.Level == LogLevel.Warning).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(1));
        // the names of the resources help to find the right one: the most common mistake is the name of the resource
        Assert.That(warnings[0].Message, Does.Contain("'WebAuthn.Net.blob.jwt'").And.Contain(TestAssembly.FullName!).And.Contain($"'{BlobResourceName}'"));
    }

    [Test]
    public async Task LoadEmbeddedMetadataAsync_WhenResourceIsMissing_WarnsWithLimitedNumberOfResourceNames()
    {
        var resources = Enumerable.Range(0, 20).ToDictionary(static x => $"Resource{x:D2}.txt", static _ => Array.Empty<byte>());
        var provider = CreateProvider(CurrentDate);

        var result = await provider.LoadEmbeddedMetadataAsync(new InMemoryResourceAssembly(resources), BlobResourceName, CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        var warning = Logger.Entries.Single(static x => x.Level == LogLevel.Warning).Message;
        Assert.That(warning, Does.Contain("'Resource15.txt', ... (20 in total)").And.Not.Contain("Resource16.txt"));
    }

    [Test]
    public async Task LoadEmbeddedMetadataAsync_WhenAssemblyHasNoResources_ReturnsFailAndWarns()
    {
        var provider = CreateProvider(CurrentDate);

        var result = await provider.LoadEmbeddedMetadataAsync(new InMemoryResourceAssembly(new Dictionary<string, byte[]>()), BlobResourceName, CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        AssertEmbeddedFailureCounted(FidoMetadataEmbeddedBlobFailures.ResourceNotFound);
        Assert.That(Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message), Has.One.Contains("<none>"));
    }

    [TestCase("<html><body>Not a blob</body></html>")]
    [TestCase("")]
    public async Task LoadEmbeddedMetadataAsync_WhenResourceIsNotJwt_ReturnsFailAndWarns(string content)
    {
        var provider = CreateProvider(CurrentDate);
        var assembly = CreateAssembly(content);

        var result = await provider.LoadEmbeddedMetadataAsync(assembly, BlobResourceName, CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        AssertEmbeddedFailureCounted(FidoMetadataEmbeddedBlobFailures.JwtMalformed);
        var warnings = Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(2));
        Assert.That(warnings[0], Does.Contain("is not a JWS (JWT)"));
        Assert.That(warnings[1], Does.Contain("embedded in the application").And.Contain("rejected: jwt_malformed"));
    }

    [Test]
    public async Task LoadEmbeddedMetadataAsync_WhenPayloadIsModified_ReturnsFail()
    {
        // The signature is verified, so a modified blob (for example, a forged status of an authenticator) is rejected.
        var segments = GetGenuineBlob().Split('.');
        var payload = JsonNode.Parse(WebEncoders.Base64UrlDecode(segments[1]))!.AsObject();
        payload["no"] = BlobNo + 1;
        var modifiedBlob = $"{segments[0]}.{WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(payload.ToJsonString()))}.{segments[2]}";
        var provider = CreateProvider(CurrentDate);

        var result = await provider.LoadEmbeddedMetadataAsync(CreateAssembly(modifiedBlob), BlobResourceName, CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        AssertEmbeddedFailureCounted(FidoMetadataEmbeddedBlobFailures.SignatureInvalid);
    }

    [Test]
    public async Task LoadEmbeddedMetadataAsync_WhenBlobIsSignedUnderAnotherRoot_ReturnsFail()
    {
        // For example, a blob of the FIDO conformance tools embedded in a production application: it doesn't chain up to the root certificates of the FIDO Metadata Service.
        var provider = CreateProvider(CurrentDate);

        var result = await provider.LoadEmbeddedMetadataAsync(CreateAssembly(ResignUnderAnotherRoot(GetGenuineBlob())), BlobResourceName, CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        AssertEmbeddedFailureCounted(FidoMetadataEmbeddedBlobFailures.ChainInvalid);
    }

    [Test]
    public async Task LoadEmbeddedMetadataAsync_TrimsLineBreakAtEndOfResource()
    {
        // A file saved by an editor or by 'curl' usually ends with a line break.
        var provider = CreateProvider(CurrentDate);

        var result = await provider.LoadEmbeddedMetadataAsync(CreateAssembly(GetGenuineBlob() + "\r\n"), BlobResourceName, CancellationToken.None);

        Assert.That(result.HasError, Is.False);
        Assert.That(result.Ok!.No, Is.EqualTo(BlobNo));
    }

    [Test]
    public async Task LoadEmbeddedMetadataAsync_WhenArgumentsAreMissing_Throws()
    {
        var provider = CreateProvider(CurrentDate);

        await Assert.ThrowsAsync<ArgumentNullException>(async () => await provider.LoadEmbeddedMetadataAsync(null!, BlobResourceName, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await provider.LoadEmbeddedMetadataAsync(TestAssembly, null!, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(async () => await provider.LoadEmbeddedMetadataAsync(TestAssembly, string.Empty, CancellationToken.None));
    }

    [Test]
    public void LoadEmbeddedMetadataAsync_WhenProviderDoesNotImplementIt_ThrowsNotSupportedException()
    {
        // A provider implemented from scratch keeps compiling: the default interface method reports that it doesn't support the embedded blob.
        IFidoMetadataProvider provider = new DownloadOnlyFidoMetadataProvider();

        var exception = Assert.Throws<NotSupportedException>(() => provider.LoadEmbeddedMetadataAsync(TestAssembly, BlobResourceName, CancellationToken.None));

        Assert.That(exception!.Message, Does.Contain(nameof(DownloadOnlyFidoMetadataProvider)));
    }

    private void AssertEmbeddedFailureCounted(string reason)
    {
        Assert.Multiple(() =>
        {
            Assert.That(Counters.EmbeddedLoadStarts, Is.EqualTo(1));
            Assert.That(Counters.SuccessfulEmbeddedLoadEnds, Is.Zero);
            Assert.That(Counters.FailedEmbeddedLoadEnds, Is.EqualTo(1));
            Assert.That(Counters.EmbeddedLoadFailures, Is.EqualTo(new[] { reason }));
            Assert.That(Counters.DownloadStarts, Is.Zero);
        });
    }

    private static string GetGenuineBlob()
    {
        return EmbeddedResourceProvider.GetString(BlobResourceName);
    }

    private static InMemoryResourceAssembly CreateAssembly(string blob)
    {
        return new(new Dictionary<string, byte[]>
        {
            [BlobResourceName] = Encoding.UTF8.GetBytes(blob)
        });
    }

    // The genuine payload signed by a certificate issued by a root that is not a root certificate of the FIDO Metadata Service.
    private static string ResignUnderAnotherRoot(string jwt)
    {
        var segments = jwt.Split('.');
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest("CN=WebAuthn.Net Test Metadata Root", rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var root = rootRequest.CreateSelfSigned(CurrentDate.AddYears(-1), CurrentDate.AddYears(1));
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signingRequest = new CertificateRequest("CN=WebAuthn.Net Test Metadata Signer", signingKey, HashAlgorithmName.SHA256);
        signingRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        using var signingCertificate = signingRequest.Create(root, CurrentDate.AddDays(-1), CurrentDate.AddDays(30), new byte[] { 1, 2, 3, 4 });
        var header = new JsonObject
        {
            ["alg"] = "ES256",
            ["typ"] = "JWT",
            ["x5c"] = new JsonArray(Convert.ToBase64String(signingCertificate.RawData), Convert.ToBase64String(root.RawData))
        };
        var signingInput = $"{WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(header.ToJsonString()))}.{segments[1]}";
        // ES256 signature is r || s (IEEE P1363), the default format of ECDsa.SignData
        var signature = signingKey.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256);
        return $"{signingInput}.{WebEncoders.Base64UrlEncode(signature)}";
    }

    private DefaultFidoMetadataProvider CreateProvider(DateTimeOffset currentDate, IFidoMetadataHttpClient? metadataHttpClient = null)
    {
        return new(
            Options,
            new DefaultSafeJsonSerializer(NullLogger<DefaultSafeJsonSerializer>.Instance),
            metadataHttpClient ?? new ThrowingFidoMetadataHttpClient(),
            new FakeTimeProvider(currentDate),
            Counters,
            Logger);
    }

    private sealed class ThrowingFidoMetadataHttpClient : IFidoMetadataHttpClient
    {
        public Task<string> DownloadMetadataAsync(CancellationToken cancellationToken)
        {
            throw new HttpRequestException("The FIDO Metadata Service must not be used");
        }
    }

    private sealed class StaticFidoMetadataHttpClient : IFidoMetadataHttpClient
    {
        private readonly string _rawMetadata;

        public StaticFidoMetadataHttpClient(string rawMetadata)
        {
            _rawMetadata = rawMetadata;
        }

        public Task<string> DownloadMetadataAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(_rawMetadata);
        }
    }

    private sealed class RejectingChainFidoMetadataProvider : DefaultFidoMetadataProvider
    {
        public RejectingChainFidoMetadataProvider(
            IOptionsMonitor<WebAuthnOptions> options,
            ISafeJsonSerializer safeJsonSerializer,
            IFidoMetadataHttpClient metadataHttpClient,
            ITimeProvider timeProvider,
            IFidoMetadataCounters counters,
            ILogger<DefaultFidoMetadataProvider> logger)
            : base(options, safeJsonSerializer, metadataHttpClient, timeProvider, counters, logger)
        {
        }

        public int Validations { get; private set; }

        protected override Task<bool> ValidateJwtCertificateChainAsync(X509Chain chain, CancellationToken cancellationToken)
        {
            Validations++;
            return Task.FromResult(false);
        }
    }

    private sealed class DownloadOnlyFidoMetadataProvider : IFidoMetadataProvider
    {
        public Task<Result<MetadataBLOBPayloadJSON>> DownloadMetadataAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(Result<MetadataBLOBPayloadJSON>.Fail());
        }
    }

    // An assembly whose manifest resources are defined by the test.
    private sealed class InMemoryResourceAssembly : Assembly
    {
        private readonly Dictionary<string, byte[]> _resources;

        public InMemoryResourceAssembly(Dictionary<string, byte[]> resources)
        {
            _resources = resources;
        }

        public override string FullName => "WebAuthn.Net.Tests.InMemoryResources, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null";

        public override Stream? GetManifestResourceStream(string name)
        {
            return _resources.TryGetValue(name, out var resource)
                ? new MemoryStream(resource, false)
                : null;
        }

        public override string[] GetManifestResourceNames()
        {
            return _resources.Keys.ToArray();
        }
    }
}
