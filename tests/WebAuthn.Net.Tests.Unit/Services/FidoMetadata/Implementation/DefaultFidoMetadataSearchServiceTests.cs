using System;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataSearchService;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Json.Implementation;
using WebAuthn.Net.Storage.FidoMetadata;
using WebAuthn.Net.Storage.FidoMetadata.Implementation;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

public class DefaultFidoMetadataSearchServiceTests
{
    private static readonly DateTimeOffset CurrentDate = DateTimeOffset.Parse("2026-10-17T17:20:02.0000000+00:00", CultureInfo.InvariantCulture);

    private DefaultFidoMetadataDecoder Decoder { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
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
            new FakeFidoMetadataCounters(),
            NullLogger<DefaultFidoMetadataDecoder>.Instance);
    }

    [TestCase("FIDO_CERTIFIED_L1", true)]
    [TestCase("RETIRED", false)]
    [TestCase("REVOKED", false)]
    [TestCase("SOME_FUTURE_STATUS", true)]
    public async Task DefaultFidoMetadataSearchService_FindMetadataByAaguidAsync_DependsOnAuthenticatorStatus(string status, bool isTrusted)
    {
        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-authnr-stat
        // An unknown status is ignored, so it doesn't affect the trust in the entry with the other (known) statuses.
        var rootCertificate = CreateRootCertificate();
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(x =>
        {
            FakeMetadataBlobPayloadJsonFactory.GetMetadataStatement(x)["attestationRootCertificates"] = new JsonArray(Convert.ToBase64String(rootCertificate));
            var statusReports = FakeMetadataBlobPayloadJsonFactory.GetEntry(x)["statusReports"]?.AsArray() ?? throw new InvalidOperationException("No status reports");
            statusReports.Add(new JsonObject
            {
                ["status"] = status,
                ["effectiveDate"] = "2026-10-01"
            });
        });
        var decodeResult = Decoder.Decode(payload);
        if (decodeResult.HasError)
        {
            throw new InvalidOperationException("Can't decode metadata");
        }

        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        await storage.UpsertAsync(decodeResult.Ok, CancellationToken.None);
        var searchService = new DefaultFidoMetadataSearchService<FakeWebAuthnContext>(storage, new FakeTimeProvider(CurrentDate));
        await using var context = new FakeWebAuthnContext(null, new());

        var result = await searchService.FindMetadataByAaguidAsync(context, Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid), CancellationToken.None);

        Assert.That(result is not null, Is.EqualTo(isTrusted));
    }

    [Test]
    public async Task DefaultFidoMetadataSearchService_FindMetadataByAaguidAsync_WhenAllStatusReportsAreUnknown_DoesNotTrustMetadata()
    {
        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-authnr-stat
        // The entry remains in the decoded blob, but without any known status report it can't be trusted.
        var rootCertificate = CreateRootCertificate();
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(x =>
        {
            FakeMetadataBlobPayloadJsonFactory.GetMetadataStatement(x)["attestationRootCertificates"] = new JsonArray(Convert.ToBase64String(rootCertificate));
            FakeMetadataBlobPayloadJsonFactory.GetEntry(x)["statusReports"] = new JsonArray(new JsonObject
            {
                ["status"] = "SOME_FUTURE_STATUS",
                ["effectiveDate"] = "2026-10-01"
            });
        });
        var decodeResult = Decoder.Decode(payload);
        if (decodeResult.HasError)
        {
            throw new InvalidOperationException("Can't decode metadata");
        }

        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        await storage.UpsertAsync(decodeResult.Ok, CancellationToken.None);
        var searchService = new DefaultFidoMetadataSearchService<FakeWebAuthnContext>(storage, new FakeTimeProvider(CurrentDate));
        await using var context = new FakeWebAuthnContext(null, new());

        var result = await searchService.FindMetadataByAaguidAsync(context, Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid), CancellationToken.None);

        Assert.That(result, Is.Null);
    }

    [Test]
    public async Task DefaultFidoMetadataSearchService_FindMetadataByAaguidAsync_BeforeFirstIngest_ReturnsNullAndWarns()
    {
        // Before the first successful ingestion the storage is empty: the lookup must fail cleanly (no exception),
        // and the absence of the metadata must be visible in the log, because no lookup can succeed until a blob is ingested.
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        var logger = new FakeLogger<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>();
        var searchService = new DefaultFidoMetadataSearchService<FakeWebAuthnContext>(storage, new FakeTimeProvider(CurrentDate), logger);
        await using var context = new FakeWebAuthnContext(null, new());

        var result = await searchService.FindMetadataByAaguidAsync(context, Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid), CancellationToken.None);

        Assert.That(result, Is.Null);
        var warnings = logger.Entries.Where(static x => x.Level == LogLevel.Warning).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(1));
        Assert.That(warnings[0].Message, Does.Contain("no blob has been ingested yet").And.Contain(FakeMetadataBlobPayloadJsonFactory.Aaguid));
    }

    [Test]
    public async Task DefaultFidoMetadataSearchService_FindMetadataBySubjectKeyIdentifierAsync_BeforeFirstIngest_ReturnsNullAndWarns()
    {
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        var logger = new FakeLogger<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>();
        var searchService = new DefaultFidoMetadataSearchService<FakeWebAuthnContext>(storage, new FakeTimeProvider(CurrentDate), logger);
        await using var context = new FakeWebAuthnContext(null, new());

        var result = await searchService.FindMetadataBySubjectKeyIdentifierAsync(context, new byte[] { 0x01, 0x02, 0xAB, 0xCD }, CancellationToken.None);

        Assert.That(result, Is.Null);
        var warnings = logger.Entries.Where(static x => x.Level == LogLevel.Warning).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(1));
        Assert.That(warnings[0].Message, Does.Contain("no blob has been ingested yet").And.Contain("0102ABCD"));
    }

    [Test]
    public async Task DefaultFidoMetadataSearchService_FindMetadataByAaguidAsync_WhenEntryIsAbsentFromIngestedBlob_ReturnsNullWithoutWarning()
    {
        // An authenticator that is absent from the ingested metadata is a normal situation (not every authenticator is certified), not an anomaly.
        var payload = FakeMetadataBlobPayloadJsonFactory.Create();
        var decodeResult = Decoder.Decode(payload);
        if (decodeResult.HasError)
        {
            throw new InvalidOperationException("Can't decode metadata");
        }

        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        await storage.UpsertAsync(decodeResult.Ok, CancellationToken.None);
        var logger = new FakeLogger<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>();
        var searchService = new DefaultFidoMetadataSearchService<FakeWebAuthnContext>(storage, new FakeTimeProvider(CurrentDate), logger);
        await using var context = new FakeWebAuthnContext(null, new());

        var result = await searchService.FindMetadataByAaguidAsync(context, Guid.Parse(FakeMetadataBlobPayloadJsonFactory.SecondAaguid), CancellationToken.None);

        Assert.That(result, Is.Null);
        Assert.That(logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
    }

    [Test]
    public async Task DefaultFidoMetadataSearchService_FindMetadataByAaguidAsync_WhenStorageDoesNotTrackMetadataAvailability_ReturnsNullWithoutWarning()
    {
        // A storage that doesn't override IFidoMetadataSearchStorage.IsMetadataAvailableAsync can't distinguish "not found" from "no metadata", so nothing is reported.
        var logger = new FakeLogger<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>();
        var searchService = new DefaultFidoMetadataSearchService<FakeWebAuthnContext>(new EmptySearchStorage(), new FakeTimeProvider(CurrentDate), logger);
        await using var context = new FakeWebAuthnContext(null, new());

        var result = await searchService.FindMetadataByAaguidAsync(context, Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid), CancellationToken.None);

        Assert.That(result, Is.Null);
        Assert.That(logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
    }

    [Test]
    public async Task DefaultFidoMetadataSearchService_FindMetadataByAaguidAsync_WhenResolvedFromDependencyInjection_ReportsAbsentMetadata()
    {
        // The container must pick the constructor with the logger (there are two constructors), otherwise the absence of the metadata would be reported nowhere.
        var logger = new FakeLogger<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IFidoMetadataSearchStorage<FakeWebAuthnContext>>(new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>());
        services.AddSingleton<ITimeProvider>(new FakeTimeProvider(CurrentDate));
        services.AddSingleton<ILogger<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>>(logger);
        services.TryAddSingleton<IFidoMetadataSearchService<FakeWebAuthnContext>, DefaultFidoMetadataSearchService<FakeWebAuthnContext>>();
        await using var serviceProvider = services.BuildServiceProvider();
        var searchService = serviceProvider.GetRequiredService<IFidoMetadataSearchService<FakeWebAuthnContext>>();
        await using var context = new FakeWebAuthnContext(null, new());

        var result = await searchService.FindMetadataByAaguidAsync(context, Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid), CancellationToken.None);

        Assert.That(searchService, Is.InstanceOf<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>());
        Assert.That(result, Is.Null);
        Assert.That(logger.Entries.Where(static x => x.Level == LogLevel.Warning), Has.Exactly(1).Items);
    }

    private sealed class EmptySearchStorage : IFidoMetadataSearchStorage<FakeWebAuthnContext>
    {
        public Task<MetadataBlobPayloadEntry?> FindByAaguidAsync(FakeWebAuthnContext context, Guid aaguid, CancellationToken cancellationToken)
        {
            return Task.FromResult<MetadataBlobPayloadEntry?>(null);
        }

        public Task<MetadataBlobPayloadEntry?> FindBySubjectKeyIdentifierAsync(FakeWebAuthnContext context, byte[] subjectKeyIdentifier, CancellationToken cancellationToken)
        {
            return Task.FromResult<MetadataBlobPayloadEntry?>(null);
        }
    }

    private static byte[] CreateRootCertificate()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=WebAuthn.Net Test Root", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var certificate = request.CreateSelfSigned(CurrentDate.AddDays(-1), CurrentDate.AddDays(1));
        return certificate.Export(X509ContentType.Cert);
    }
}
