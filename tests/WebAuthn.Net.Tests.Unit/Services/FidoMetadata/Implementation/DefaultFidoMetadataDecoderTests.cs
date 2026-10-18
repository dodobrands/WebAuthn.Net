using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;
using WebAuthn.Net.Services.Serialization.Json.Implementation;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

public class DefaultFidoMetadataDecoderTests
{
    private OptionsMonitor<WebAuthnOptions> Options { get; set; } = null!;
    private ConfigurationManager ConfigurationManager { get; set; } = null!;
    private FakeFidoMetadataHttpClientProvider FakeFidoHttpClientProvider { get; set; } = null!;
    private DefaultFidoMetadataProvider MetadataProvider { get; set; } = null!;
    private DefaultFidoMetadataDecoder Decoder { get; set; } = null!;
    private FakeFidoMetadataCounters Counters { get; set; } = null!;
    private MetadataBLOBPayloadJSON PayloadToDecode { get; set; } = null!;

    [SetUp]
    public async Task SetupServices()
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
        FakeFidoHttpClientProvider = new();
        Counters = new();
        var safeJsonDeserializer = new DefaultSafeJsonSerializer(NullLogger<DefaultSafeJsonSerializer>.Instance);
        MetadataProvider = new(
            Options,
            safeJsonDeserializer,
            FakeFidoHttpClientProvider.Client,
            new FakeTimeProvider(DateTimeOffset.Parse("2026-10-17T17:20:02.0000000+00:00", CultureInfo.InvariantCulture)),
            NullLogger<DefaultFidoMetadataProvider>.Instance);
        Decoder = new(
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
        var result = await MetadataProvider.DownloadMetadataAsync(CancellationToken.None);
        if (result.HasError)
        {
            throw new InvalidOperationException("Can't get metadata to decode");
        }

        PayloadToDecode = result.Ok;
    }

    [TearDown]
    public virtual void TearDownServices()
    {
        FakeFidoHttpClientProvider.Dispose();
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenCorrectDataProvided()
    {
        var result = Decoder.Decode(PayloadToDecode);
        Assert.That(result.HasError, Is.False);
        Assert.That(result.Ok, Is.Not.Null);
        // all entries of the real blob must be decoded, none of them may be skipped
        Assert.That(result.Ok?.Entries, Has.Length.EqualTo(PayloadToDecode.Entries.Length));
        Assert.That(Counters.SkippedEntries, Is.Empty);
        // every status of the real blob must be known to the library, otherwise the AuthenticatorStatus enum is outdated
        Assert.That(Counters.IgnoredStatusReports, Is.Empty);
        Assert.That(Counters.SuccessfulDecodeEnds, Is.EqualTo(1));
    }
}
