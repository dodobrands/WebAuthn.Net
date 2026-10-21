using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
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
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;
using WebAuthn.Net.Services.Serialization.Json.Implementation;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

// The blob must be signed with the key of the first certificate from the 'x5c' member of its JWT header (RFC 7515 4.1.6): only the chain of that certificate is validated,
// the other certificates merely help to build it. The tests use the genuine blob and its genuine signing certificate chain, so the chain is valid and only the signature decides.
public class DefaultFidoMetadataProviderSigningKeyTests
{
    private static readonly DateTimeOffset CurrentDate = DateTimeOffset.Parse("2026-10-17T17:20:02.0000000+00:00", CultureInfo.InvariantCulture);

    private OptionsMonitor<WebAuthnOptions> Options { get; set; } = null!;
    private ConfigurationManager ConfigurationManager { get; set; } = null!;
    private FakeLogger<DefaultFidoMetadataProvider> Logger { get; set; } = null!;

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
    }

    [TearDown]
    public void TearDownServices()
    {
        Options.Dispose();
        ConfigurationManager.Dispose();
    }

    [Test]
    public async Task DefaultFidoMetadataProvider_DownloadMetadata_WhenJwtIsSignedWithKeyOfFirstCertificateInX5C_ReturnsSuccess()
    {
        // The genuine blob, signed by the FIDO Alliance with the key of the first certificate from its 'x5c'.
        var provider = CreateProvider(new StaticFidoMetadataHttpClient(GetGenuineBlob()));

        var result = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.False);
        Assert.That(Logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
    }

    [Test]
    public async Task DefaultFidoMetadataProvider_DownloadMetadata_WhenJwtIsSignedWithKeyOfCertificateThatFollowsFirstInX5C_ReturnsFailAndWarns()
    {
        // The genuine 'x5c' followed by the attacker's own certificate, whose key signed the blob: the chain of the first certificate is still valid,
        // so accepting the key of any certificate from 'x5c' would let anyone who can serve a blob (a proxy, a mirror, a man in the middle) forge the metadata.
        var provider = CreateProvider(new StaticFidoMetadataHttpClient(ResignWithAppendedCertificate(GetGenuineBlob())));

        var result = await provider.DownloadMetadataAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.True);
        var warnings = Logger.Entries.Where(static x => x.Level == LogLevel.Warning).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(1));
        Assert.That(warnings[0].Message, Does.Contain("signature of the FIDO Metadata Service blob JWT"));
    }

    private static string GetGenuineBlob()
    {
        return EmbeddedResourceProvider.GetString("WebAuthn.Net.DSL.Fakes.FakeResources.blob.jwt");
    }

    private static string ResignWithAppendedCertificate(string jwt)
    {
        var segments = jwt.Split('.');
        var header = JsonNode.Parse(WebEncoders.Base64UrlDecode(segments[0]))!.AsObject();
        using var attackerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var attackerCertificate = new CertificateRequest("CN=Appended Certificate", attackerKey, HashAlgorithmName.SHA256).CreateSelfSigned(CurrentDate.AddDays(-1), CurrentDate.AddDays(30));
        header["alg"] = "ES256";
        header["x5c"]!.AsArray().Add(Convert.ToBase64String(attackerCertificate.RawData));
        var signingInput = $"{WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(header.ToJsonString()))}.{segments[1]}";
        // ES256 signature is r || s (IEEE P1363), the default format of ECDsa.SignData
        var signature = attackerKey.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256);
        return $"{signingInput}.{WebEncoders.Base64UrlEncode(signature)}";
    }

    private DefaultFidoMetadataProvider CreateProvider(IFidoMetadataHttpClient metadataHttpClient)
    {
        return new(
            Options,
            new DefaultSafeJsonSerializer(NullLogger<DefaultSafeJsonSerializer>.Instance),
            metadataHttpClient,
            new FakeTimeProvider(CurrentDate),
            Logger);
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
}
