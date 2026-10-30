using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
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
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Serialization.Json.Implementation;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

// The signing certificate of the blob has to be the certificate of the FIDO Metadata Service: issued to FidoMetadataOptions.SigningCertificateDnsName (mds.fidoalliance.org by default)
// for TLS server authentication. Most tests sign the genuine payload (no: 291) with certificates issued under a test root, which the provider trusts instead of the root certificates
// of the FIDO Metadata Service, so that the chain is valid and only the signing certificate decides.
public class DefaultFidoMetadataProviderSignerTests
{
    private const string BlobResourceName = "WebAuthn.Net.DSL.Fakes.FakeResources.blob.jwt";
    private const long BlobNo = 291;
    private const string FidoMetadataServiceDnsName = "mds.fidoalliance.org";
    private const string SignerSubject = "CN=WebAuthn.Net Test Metadata Signer";
    private const string ServerAuthentication = "1.3.6.1.5.5.7.3.1";
    private const string ClientAuthentication = "1.3.6.1.5.5.7.3.2";
    private const string AnyExtendedKeyUsage = "2.5.29.37.0";

    private static readonly DateTimeOffset CurrentDate = DateTimeOffset.Parse("2026-10-17T17:20:02.0000000+00:00", CultureInfo.InvariantCulture);

    private OptionsMonitor<WebAuthnOptions> Options { get; set; } = null!;
    private WebAuthnOptions WebAuthnOptions { get; set; } = null!;
    private ConfigurationManager ConfigurationManager { get; set; } = null!;
    private FakeFidoMetadataCounters Counters { get; set; } = null!;
    private FakeLogger<DefaultFidoMetadataProvider> Logger { get; set; } = null!;
    private ECDsa RootKey { get; set; } = null!;
    private X509Certificate2 Root { get; set; } = null!;

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
        RootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest("CN=WebAuthn.Net Test Metadata Root", RootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        Root = rootRequest.CreateSelfSigned(CurrentDate.AddYears(-1), CurrentDate.AddYears(1));
    }

    [TearDown]
    public void TearDownServices()
    {
        Root.Dispose();
        RootKey.Dispose();
        Options.Dispose();
        ConfigurationManager.Dispose();
    }

    [Test]
    public async Task DownloadMetadataAsync_WhenSignerIsIssuedToFidoMetadataServiceForTlsServerAuthentication_ReturnsPayload()
    {
        var provider = CreateTestRootProvider(SignGenuinePayload(FidoMetadataServiceDnsName, ServerAuthentication));

        var result = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.False);
        Assert.That(result.Ok!.No, Is.EqualTo(BlobNo));
        Assert.That(Logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
        Assert.That(Counters.SuccessfulDownloadEnds, Is.EqualTo(1));
    }

    [TestCase("metadata.example.com")]
    [TestCase("fidoalliance.org")]
    [TestCase("www.mds.fidoalliance.org")]
    [TestCase("mds.fidoalliance.org.example.com")]
    [TestCase("*.fidoalliance.org")]
    public async Task DownloadMetadataAsync_WhenSignerIsIssuedToAnotherDnsName_ReturnsFailAndWarns(string dnsName)
    {
        // For example, a certificate that the same certification authority issued for another domain. A wildcard name is not an exact match either.
        var provider = CreateTestRootProvider(SignGenuinePayload(dnsName, ServerAuthentication));

        var result = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        var warnings = Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(1));
        Assert.That(warnings[0], Does.Contain($"'{SignerSubject}'").And.Contain("is not a certificate of the FIDO Metadata Service").And.Contain($"'{FidoMetadataServiceDnsName}'"));
        AssertDownloadFailureCounted(FidoMetadataDownloadFailures.SignerInvalid);
    }

    [Test]
    public async Task DownloadMetadataAsync_WhenDnsNameIsOnlyInCommonNameOfSigner_ReturnsFail()
    {
        // Only the Subject Alternative Name extension identifies the host, as for a TLS client.
        var provider = CreateTestRootProvider(SignGenuinePayload(null, ServerAuthentication, $"CN={FidoMetadataServiceDnsName}"));

        var result = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        AssertDownloadFailureCounted(FidoMetadataDownloadFailures.SignerInvalid);
    }

    [TestCase(ClientAuthentication)]
    [TestCase(AnyExtendedKeyUsage)]
    public async Task DownloadMetadataAsync_WhenSignerIsNotForTlsServerAuthentication_ReturnsFail(string extendedKeyUsage)
    {
        var provider = CreateTestRootProvider(SignGenuinePayload(FidoMetadataServiceDnsName, extendedKeyUsage));

        var result = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        AssertDownloadFailureCounted(FidoMetadataDownloadFailures.SignerInvalid);
    }

    [Test]
    public async Task DownloadMetadataAsync_WhenSignerHasNoExtendedKeyUsage_ReturnsFail()
    {
        var provider = CreateTestRootProvider(SignGenuinePayload(FidoMetadataServiceDnsName, null));

        var result = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        AssertDownloadFailureCounted(FidoMetadataDownloadFailures.SignerInvalid);
    }

    [Test]
    public async Task DownloadMetadataAsync_WhenSubjectAlternativeNameOfSignerIsMalformed_ReturnsFail()
    {
        // The extension is decoded only when the DNS name is checked, so a malformed one must be a rejection, not an exception.
        var provider = CreateTestRootProvider(SignGenuinePayloadWithExtensions(SignerSubject, static request =>
        {
            request.CertificateExtensions.Add(new X509Extension("2.5.29.17", new byte[] { 0x30, 0x05, 0x82, 0x09, 0x41 }, false));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(ServerAuthentication) }, false));
        }));

        var result = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        AssertDownloadFailureCounted(FidoMetadataDownloadFailures.SignerInvalid);
    }

    [Test]
    public async Task DownloadMetadataAsync_ChecksSignerBeforeBuildingChain()
    {
        // The chain (with the revocation checks of its policy) is not built for the certificates of another signer.
        var chainBuilds = 0;
        var configureChain = WebAuthnOptions.X509ChainValidation.OnValidateFidoMetadataBlobJwtChain;
        WebAuthnOptions.X509ChainValidation.OnValidateFidoMetadataBlobJwtChain = chain =>
        {
            chainBuilds++;
            configureChain(chain);
        };
        var provider = CreateTestRootProvider(SignGenuinePayload("metadata.example.com", ServerAuthentication));

        var result = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        AssertDownloadFailureCounted(FidoMetadataDownloadFailures.SignerInvalid);
        Assert.That(chainBuilds, Is.Zero);
    }

    [Test]
    public async Task DownloadMetadataAsync_WhenAnotherDnsNameIsConfigured_ReturnsPayloadSignedForIt()
    {
        WebAuthnOptions.FidoMetadata.SigningCertificateDnsName = "metadata.example.com";
        var provider = CreateTestRootProvider(SignGenuinePayload("metadata.example.com", ServerAuthentication));

        var result = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.False);
        Assert.That(result.Ok!.No, Is.EqualTo(BlobNo));
    }

    [Test]
    public async Task DownloadMetadataAsync_WhenAnotherDnsNameIsConfigured_RejectsGenuineBlob()
    {
        // The genuine blob is accepted only because its signing certificate is issued to mds.fidoalliance.org.
        WebAuthnOptions.FidoMetadata.SigningCertificateDnsName = "metadata.example.com";
        var provider = CreateProvider(GetGenuineBlob());

        var result = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        var warning = Logger.Entries.Single(static x => x.Level == LogLevel.Warning).Message;
        Assert.That(warning, Does.Contain("CN=mds.fidoalliance.org").And.Contain("'metadata.example.com'"));
        AssertDownloadFailureCounted(FidoMetadataDownloadFailures.SignerInvalid);
    }

    [Test]
    public async Task DownloadMetadataAsync_WhenDnsNameIsNotConfigured_ReturnsPayloadOfAnySignerUnderRoot()
    {
        // A test environment that signs its blobs under its own root, for example, the MDS3 test server of the FIDO Conformance Tools.
        WebAuthnOptions.FidoMetadata.SigningCertificateDnsName = null;
        var provider = CreateTestRootProvider(SignGenuinePayload(null, null));

        var result = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.False);
        Assert.That(Logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
    }

    [Test]
    public async Task DownloadMetadataAsync_WhenDnsNameIsNotConfigured_StillValidatesChain()
    {
        WebAuthnOptions.FidoMetadata.SigningCertificateDnsName = null;
        // the blob is signed under the test root, but the provider trusts only the root certificates of the FIDO Metadata Service
        var provider = CreateProvider(SignGenuinePayload(null, null));

        var result = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        AssertDownloadFailureCounted(FidoMetadataDownloadFailures.ChainInvalid);
    }

    [TestCase("")]
    [TestCase("*.fidoalliance.org")]
    public async Task DownloadMetadataAsync_WhenConfiguredDnsNameIsInvalid_ThrowsArgumentException(string dnsName)
    {
        // A configuration error, not a property of the blob: it fails every load loudly instead of being counted as a rejected blob.
        WebAuthnOptions.FidoMetadata.SigningCertificateDnsName = dnsName;
        var provider = CreateProvider(GetGenuineBlob());

        await Assert.ThrowsAsync<ArgumentException>(async () => await provider.DownloadMetadataAsync(CancellationToken.None));
    }

    [Test]
    public async Task LoadEmbeddedMetadataAsync_WhenSignerIsIssuedToAnotherDnsName_ReturnsFailAndWarns()
    {
        // The signing certificate of the blob embedded in the application is checked like that of a downloaded blob.
        var provider = CreateTestRootProvider(GetGenuineBlob());

        var result = await provider.LoadEmbeddedMetadataAsync(new BlobResourceAssembly(SignGenuinePayload("metadata.example.com", ServerAuthentication)), BlobResourceName, CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        Assert.Multiple(() =>
        {
            Assert.That(Counters.FailedEmbeddedLoadEnds, Is.EqualTo(1));
            Assert.That(Counters.EmbeddedLoadFailures, Is.EqualTo(new[] { FidoMetadataEmbeddedBlobFailures.SignerInvalid }));
        });
        var warnings = Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(2));
        Assert.That(warnings[0], Does.Contain("is not a certificate of the FIDO Metadata Service"));
        Assert.That(warnings[1], Does.Contain("embedded in the application").And.Contain("rejected: signer_invalid"));
    }

    [Test]
    public async Task LoadEmbeddedMetadataAsync_WhenSignerIsIssuedToFidoMetadataService_ReturnsPayload()
    {
        var provider = CreateTestRootProvider(GetGenuineBlob());

        var result = await provider.LoadEmbeddedMetadataAsync(new BlobResourceAssembly(SignGenuinePayload(FidoMetadataServiceDnsName, ServerAuthentication)), BlobResourceName, CancellationToken.None);

        Assert.That(result.HasError, Is.False);
        Assert.That(result.Ok!.No, Is.EqualTo(BlobNo));
    }

    private void AssertDownloadFailureCounted(string reason)
    {
        Assert.Multiple(() =>
        {
            Assert.That(Counters.DownloadStarts, Is.EqualTo(1));
            Assert.That(Counters.SuccessfulDownloadEnds, Is.Zero);
            Assert.That(Counters.FailedDownloadEnds, Is.EqualTo(1));
            Assert.That(Counters.DownloadFailures, Is.EqualTo(new[] { reason }));
        });
    }

    private static string GetGenuineBlob()
    {
        return EmbeddedResourceProvider.GetString(BlobResourceName);
    }

    // The genuine payload signed by a certificate issued under the test root, with the given DNS name in its Subject Alternative Name extension and the given extended key usage (null - without the extension).
    private string SignGenuinePayload(string? dnsName, string? extendedKeyUsage, string subject = SignerSubject)
    {
        return SignGenuinePayloadWithExtensions(subject, request =>
        {
            if (dnsName is not null)
            {
                var subjectAlternativeName = new SubjectAlternativeNameBuilder();
                subjectAlternativeName.AddDnsName(dnsName);
                request.CertificateExtensions.Add(subjectAlternativeName.Build());
            }

            if (extendedKeyUsage is not null)
            {
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(extendedKeyUsage) }, false));
            }
        });
    }

    private string SignGenuinePayloadWithExtensions(string subject, Action<CertificateRequest> addExtensions)
    {
        var payload = GetGenuineBlob().Split('.')[1];
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signingRequest = new CertificateRequest(subject, signingKey, HashAlgorithmName.SHA256);
        signingRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        signingRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        addExtensions(signingRequest);
        using var signingCertificate = signingRequest.Create(Root, CurrentDate.AddDays(-1), CurrentDate.AddDays(30), new byte[] { 1, 2, 3, 4 });
        var header = new JsonObject
        {
            ["alg"] = "ES256",
            ["typ"] = "JWT",
            ["x5c"] = new JsonArray(Convert.ToBase64String(signingCertificate.RawData), Convert.ToBase64String(Root.RawData))
        };
        var signingInput = $"{WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(header.ToJsonString()))}.{payload}";
        // ES256 signature is r || s (IEEE P1363), the default format of ECDsa.SignData
        var signature = signingKey.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256);
        return $"{signingInput}.{WebEncoders.Base64UrlEncode(signature)}";
    }

    // the provider that trusts the root certificates of the FIDO Metadata Service embedded in the library
    private DefaultFidoMetadataProvider CreateProvider(string rawMetadata)
    {
        return new(
            Options,
            new DefaultSafeJsonSerializer(NullLogger<DefaultSafeJsonSerializer>.Instance),
            new StaticFidoMetadataHttpClient(rawMetadata),
            new FakeTimeProvider(CurrentDate),
            Counters,
            Logger);
    }

    // the provider that trusts only the test root
    private TestRootFidoMetadataProvider CreateTestRootProvider(string rawMetadata)
    {
        return new(
            Options,
            new DefaultSafeJsonSerializer(NullLogger<DefaultSafeJsonSerializer>.Instance),
            new StaticFidoMetadataHttpClient(rawMetadata),
            new FakeTimeProvider(CurrentDate),
            Counters,
            Logger,
            Root.RawData);
    }

    private sealed class TestRootFidoMetadataProvider : DefaultFidoMetadataProvider
    {
        private readonly byte[] _root;

        public TestRootFidoMetadataProvider(
            IOptionsMonitor<WebAuthnOptions> options,
            ISafeJsonSerializer safeJsonSerializer,
            IFidoMetadataHttpClient metadataHttpClient,
            ITimeProvider timeProvider,
            IFidoMetadataCounters counters,
            ILogger<DefaultFidoMetadataProvider> logger,
            byte[] root)
            : base(options, safeJsonSerializer, metadataHttpClient, timeProvider, counters, logger)
        {
            _root = root;
        }

        protected override UniqueByteArraysCollection GetEmbeddedFidoRootCertificates()
        {
            return new(new[] { _root });
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

    // An assembly whose only manifest resource is the blob.
    private sealed class BlobResourceAssembly : Assembly
    {
        private readonly byte[] _blob;

        public BlobResourceAssembly(string blob)
        {
            _blob = Encoding.UTF8.GetBytes(blob);
        }

        public override string FullName => "WebAuthn.Net.Tests.BlobResource, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null";

        public override Stream? GetManifestResourceStream(string name)
        {
            return name == BlobResourceName
                ? new MemoryStream(_blob, false)
                : null;
        }

        public override string[] GetManifestResourceNames()
        {
            return new[] { BlobResourceName };
        }
    }
}
