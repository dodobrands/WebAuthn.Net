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
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataSearchService;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService.Enums;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Json.Implementation;
using WebAuthn.Net.Storage.FidoMetadata;
using WebAuthn.Net.Storage.FidoMetadata.Implementation;
using WebAuthn.Net.Storage.FidoMetadata.Models.Enums;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

public class DefaultFidoMetadataSearchServiceTests
{
    private static readonly DateTimeOffset CurrentDate = DateTimeOffset.Parse("2026-10-17T17:20:02.0000000+00:00", CultureInfo.InvariantCulture);
    private static readonly byte[] SubjectKeyIdentifier = { 0x01, 0x02, 0xAB, 0xCD };

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

    [TestCase("FIDO_CERTIFIED_L1", null)]
    [TestCase("RETIRED", FidoMetadataSearchError.Untrusted)]
    [TestCase("REVOKED", FidoMetadataSearchError.Untrusted)]
    [TestCase("ATTESTATION_KEY_COMPROMISE", FidoMetadataSearchError.Untrusted)]
    [TestCase("SOME_FUTURE_STATUS", null)]
    public async Task DefaultFidoMetadataSearchService_FindMetadataByAaguidAsync_DependsOnAuthenticatorStatus(string status, FidoMetadataSearchError? expectedError)
    {
        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-authnr-stat
        // An unknown status is ignored, so it doesn't affect the trust in the entry with the other (known) statuses.
        var storage = await CreateStorageAsync(x => AddStatusReport(x, status));
        var counters = new FakeFidoMetadataCounters();
        var searchService = new DefaultFidoMetadataSearchService<FakeWebAuthnContext>(storage, new FakeTimeProvider(CurrentDate), counters, new FakeLogger<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>());
        await using var context = new FakeWebAuthnContext(null, new());

        var result = await searchService.FindMetadataByAaguidAsync(context, Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.EqualTo(expectedError.HasValue));
            Assert.That(result.Error, Is.EqualTo(expectedError));
            Assert.That(counters.LookupsWithUntrustedEntry, Is.EqualTo(expectedError.HasValue ? 1 : 0));
        });
    }

    [Test]
    public async Task DefaultFidoMetadataSearchService_FindMetadataByAaguidAsync_WhenEntryIsUntrusted_ReturnsUntrustedAndWarns()
    {
        // The status reports of the FIDO Metadata Service are the only way the library learns that an authenticator model is revoked,
        // so an untrusted entry is reported to the caller (which rejects the attestation) and is visible in the log and the metrics.
        var storage = await CreateStorageAsync(x => AddStatusReport(x, "REVOKED"));
        var counters = new FakeFidoMetadataCounters();
        var logger = new FakeLogger<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>();
        var searchService = new DefaultFidoMetadataSearchService<FakeWebAuthnContext>(storage, new FakeTimeProvider(CurrentDate), counters, logger);
        await using var context = new FakeWebAuthnContext(null, new());

        var result = await searchService.FindMetadataByAaguidAsync(context, Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid), CancellationToken.None);

        var warnings = logger.Entries.Where(static x => x.Level == LogLevel.Warning).ToArray();
        Assert.Multiple(() =>
        {
            Assert.That(result.Error, Is.EqualTo(FidoMetadataSearchError.Untrusted));
            Assert.That(warnings, Has.Length.EqualTo(1));
            Assert.That(warnings[0].Message, Is.EqualTo(
                $"The status reports of the FIDO Metadata Service entry for the authenticator with AAGUID {FakeMetadataBlobPayloadJsonFactory.Aaguid} don't allow to trust the authenticator: FIDO_CERTIFIED_L1, REVOKED"));
            Assert.That(counters.LookupsWithUntrustedEntry, Is.EqualTo(1));
            Assert.That(counters.LookupsWithoutMetadata, Is.Zero);
        });
    }

    [Test]
    public async Task DefaultFidoMetadataSearchService_FindMetadataByAaguidAsync_WhenAllStatusReportsAreUnknown_DoesNotTrustMetadata()
    {
        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-authnr-stat
        // The entry remains in the decoded blob, but without any known status report it can't be trusted.
        var storage = await CreateStorageAsync(x =>
        {
            FakeMetadataBlobPayloadJsonFactory.GetEntry(x)["statusReports"] = new JsonArray(new JsonObject
            {
                ["status"] = "SOME_FUTURE_STATUS",
                ["effectiveDate"] = "2026-10-01"
            });
        });
        var logger = new FakeLogger<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>();
        var searchService = new DefaultFidoMetadataSearchService<FakeWebAuthnContext>(storage, new FakeTimeProvider(CurrentDate), new FakeFidoMetadataCounters(), logger);
        await using var context = new FakeWebAuthnContext(null, new());

        var result = await searchService.FindMetadataByAaguidAsync(context, Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.Error, Is.EqualTo(FidoMetadataSearchError.Untrusted));
            Assert.That(logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message), Has.Exactly(1).EndsWith(": none known to the library"));
        });
    }

    [TestCase(AuthenticatorStatus.REVOKED, FidoMetadataSearchError.Untrusted)]
    [TestCase(AuthenticatorStatus.FIDO_CERTIFIED_L1, FidoMetadataSearchError.NotFound)]
    public async Task DefaultFidoMetadataSearchService_FindMetadataByAaguidAsync_WhenEntryHasNoMetadataStatement_ChecksStatusFirst(AuthenticatorStatus status, FidoMetadataSearchError expectedError)
    {
        // The metadata statement is optional in an entry of the blob, but the status reports are not: an entry without a metadata statement can't supply root certificates,
        // and it still has to reject an untrusted authenticator, whose attestation may chain up to a root certificate embedded in the library.
        var aaguid = Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid);
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        await storage.UpsertAsync(CreateBlob(new MetadataBlobPayloadEntry(null, aaguid, null, null, null, new[] { CreateStatusReport(status) }, DateTimeOffset.UnixEpoch, null, null)), CancellationToken.None);
        var searchService = new DefaultFidoMetadataSearchService<FakeWebAuthnContext>(storage, new FakeTimeProvider(CurrentDate), new FakeFidoMetadataCounters(), new FakeLogger<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>());
        await using var context = new FakeWebAuthnContext(null, new());

        var result = await searchService.FindMetadataByAaguidAsync(context, aaguid, CancellationToken.None);

        Assert.That(result.Error, Is.EqualTo(expectedError));
    }

    [TestCase(AuthenticatorStatus.REVOKED, FidoMetadataSearchError.Untrusted, 1)]
    [TestCase(AuthenticatorStatus.FIDO_CERTIFIED_L1, FidoMetadataSearchError.NotFound, 0)]
    public async Task DefaultFidoMetadataSearchService_FindMetadataBySubjectKeyIdentifierAsync_DependsOnAuthenticatorStatus(AuthenticatorStatus status, FidoMetadataSearchError expectedError, int expectedWarnings)
    {
        // the entry has no metadata statement, so even a trusted one can't be used: the status decides between Untrusted and NotFound
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        await storage.UpsertAsync(CreateBlob(new MetadataBlobPayloadEntry(null, null, new[] { SubjectKeyIdentifier }, null, null, new[] { CreateStatusReport(status) }, DateTimeOffset.UnixEpoch, null, null)), CancellationToken.None);
        var counters = new FakeFidoMetadataCounters();
        var logger = new FakeLogger<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>();
        var searchService = new DefaultFidoMetadataSearchService<FakeWebAuthnContext>(storage, new FakeTimeProvider(CurrentDate), counters, logger);
        await using var context = new FakeWebAuthnContext(null, new());

        var result = await searchService.FindMetadataBySubjectKeyIdentifierAsync(context, SubjectKeyIdentifier, CancellationToken.None);

        var warnings = logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message).ToArray();
        Assert.Multiple(() =>
        {
            Assert.That(result.Error, Is.EqualTo(expectedError));
            Assert.That(warnings, Has.Length.EqualTo(expectedWarnings));
            Assert.That(warnings, Has.All.Contains("0102ABCD"));
            Assert.That(warnings, Has.All.EndsWith(": REVOKED"));
            Assert.That(counters.LookupsWithUntrustedEntry, Is.EqualTo(expectedWarnings));
        });
    }

    [Test]
    public async Task DefaultFidoMetadataSearchService_FindMetadataByAaguidAsync_BeforeFirstIngest_ReturnsMetadataNotAvailableAndWarns()
    {
        // Before the first successful ingestion the storage is empty: the lookup must fail cleanly (no exception),
        // and the absence of the metadata must be visible in the log and the metrics, because no lookup can succeed until a blob is ingested.
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        var counters = new FakeFidoMetadataCounters();
        var logger = new FakeLogger<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>();
        var searchService = new DefaultFidoMetadataSearchService<FakeWebAuthnContext>(storage, new FakeTimeProvider(CurrentDate), counters, logger);
        await using var context = new FakeWebAuthnContext(null, new());

        var result = await searchService.FindMetadataByAaguidAsync(context, Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid), CancellationToken.None);

        Assert.That(result.Error, Is.EqualTo(FidoMetadataSearchError.MetadataNotAvailable));
        var warnings = logger.Entries.Where(static x => x.Level == LogLevel.Warning).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(1));
        Assert.That(warnings[0].Message, Does.Contain("no blob has been ingested yet").And.Contain(FakeMetadataBlobPayloadJsonFactory.Aaguid));
        Assert.That(counters.LookupsWithoutMetadata, Is.EqualTo(1));
        Assert.That(counters.LookupsWithUntrustedEntry, Is.Zero);
    }

    [Test]
    public async Task DefaultFidoMetadataSearchService_FindMetadataBySubjectKeyIdentifierAsync_BeforeFirstIngest_ReturnsMetadataNotAvailableAndWarns()
    {
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        var counters = new FakeFidoMetadataCounters();
        var logger = new FakeLogger<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>();
        var searchService = new DefaultFidoMetadataSearchService<FakeWebAuthnContext>(storage, new FakeTimeProvider(CurrentDate), counters, logger);
        await using var context = new FakeWebAuthnContext(null, new());

        var result = await searchService.FindMetadataBySubjectKeyIdentifierAsync(context, SubjectKeyIdentifier, CancellationToken.None);

        Assert.That(result.Error, Is.EqualTo(FidoMetadataSearchError.MetadataNotAvailable));
        var warnings = logger.Entries.Where(static x => x.Level == LogLevel.Warning).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(1));
        Assert.That(warnings[0].Message, Does.Contain("no blob has been ingested yet").And.Contain("0102ABCD"));
        Assert.That(counters.LookupsWithoutMetadata, Is.EqualTo(1));
    }

    [Test]
    public async Task DefaultFidoMetadataSearchService_FindMetadataByAaguidAsync_WhenEntryIsAbsentFromIngestedBlob_ReturnsNotFoundWithoutWarning()
    {
        // An authenticator that is absent from the ingested metadata is a normal situation (not every authenticator is certified), not an anomaly.
        var storage = await CreateStorageAsync();
        var counters = new FakeFidoMetadataCounters();
        var logger = new FakeLogger<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>();
        var searchService = new DefaultFidoMetadataSearchService<FakeWebAuthnContext>(storage, new FakeTimeProvider(CurrentDate), counters, logger);
        await using var context = new FakeWebAuthnContext(null, new());

        var result = await searchService.FindMetadataByAaguidAsync(context, Guid.Parse(FakeMetadataBlobPayloadJsonFactory.SecondAaguid), CancellationToken.None);

        Assert.That(result.Error, Is.EqualTo(FidoMetadataSearchError.NotFound));
        Assert.That(logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
        Assert.That(counters.LookupsWithoutMetadata, Is.Zero);
        Assert.That(counters.LookupsWithUntrustedEntry, Is.Zero);
    }

    [TestCase(FidoMetadataSearchStorageError.NotFound, FidoMetadataSearchError.NotFound, 0)]
    [TestCase(FidoMetadataSearchStorageError.MetadataNotAvailable, FidoMetadataSearchError.MetadataNotAvailable, 1)]
    public async Task DefaultFidoMetadataSearchService_FindMetadataByAaguidAsync_ReportsErrorOfCustomStorage(FidoMetadataSearchStorageError storageError, FidoMetadataSearchError expectedError, int expectedLookupsWithoutMetadata)
    {
        // A custom storage tells "no entry" from "no metadata" by itself, and the search service reports only the latter as an anomaly.
        var counters = new FakeFidoMetadataCounters();
        var logger = new FakeLogger<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>();
        var searchService = new DefaultFidoMetadataSearchService<FakeWebAuthnContext>(new FailingSearchStorage(storageError), new FakeTimeProvider(CurrentDate), counters, logger);
        await using var context = new FakeWebAuthnContext(null, new());

        var byAaguid = await searchService.FindMetadataByAaguidAsync(context, Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid), CancellationToken.None);
        var bySubjectKeyIdentifier = await searchService.FindMetadataBySubjectKeyIdentifierAsync(context, SubjectKeyIdentifier, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(byAaguid.Error, Is.EqualTo(expectedError));
            Assert.That(bySubjectKeyIdentifier.Error, Is.EqualTo(expectedError));
            Assert.That(logger.Entries.Where(static x => x.Level == LogLevel.Warning), Has.Exactly(2 * expectedLookupsWithoutMetadata).Items);
            Assert.That(counters.LookupsWithoutMetadata, Is.EqualTo(2 * expectedLookupsWithoutMetadata));
        });
    }

    [Test]
    public async Task DefaultFidoMetadataSearchService_FindMetadataByAaguidAsync_WhenResolvedFromDependencyInjection_ReportsAbsentMetadata()
    {
        // The container must pick the constructor with the counters and the logger (there are two constructors), otherwise the absence of the metadata would be reported nowhere.
        var counters = new FakeFidoMetadataCounters();
        var logger = new FakeLogger<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IFidoMetadataSearchStorage<FakeWebAuthnContext>>(new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>());
        services.AddSingleton<ITimeProvider>(new FakeTimeProvider(CurrentDate));
        services.AddSingleton<IFidoMetadataCounters>(counters);
        services.AddSingleton<ILogger<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>>(logger);
        services.TryAddSingleton<IFidoMetadataSearchService<FakeWebAuthnContext>, DefaultFidoMetadataSearchService<FakeWebAuthnContext>>();
        await using var serviceProvider = services.BuildServiceProvider();
        var searchService = serviceProvider.GetRequiredService<IFidoMetadataSearchService<FakeWebAuthnContext>>();
        await using var context = new FakeWebAuthnContext(null, new());

        var result = await searchService.FindMetadataByAaguidAsync(context, Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid), CancellationToken.None);

        Assert.That(searchService, Is.InstanceOf<DefaultFidoMetadataSearchService<FakeWebAuthnContext>>());
        Assert.That(result.Error, Is.EqualTo(FidoMetadataSearchError.MetadataNotAvailable));
        Assert.That(logger.Entries.Where(static x => x.Level == LogLevel.Warning), Has.Exactly(1).Items);
        Assert.That(counters.LookupsWithoutMetadata, Is.EqualTo(1));
    }

    // an in-memory storage with the fake blob (its entry has a valid root certificate), optionally modified
    private async Task<DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>> CreateStorageAsync(Action<JsonObject>? configure = null)
    {
        var rootCertificate = CreateRootCertificate();
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(x =>
        {
            FakeMetadataBlobPayloadJsonFactory.GetMetadataStatement(x)["attestationRootCertificates"] = new JsonArray(Convert.ToBase64String(rootCertificate));
            configure?.Invoke(x);
        });
        var decodeResult = Decoder.Decode(payload);
        if (decodeResult.HasError)
        {
            throw new InvalidOperationException("Can't decode metadata");
        }

        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        await storage.UpsertAsync(decodeResult.Ok, CancellationToken.None);
        return storage;
    }

    private static void AddStatusReport(JsonObject payload, string status)
    {
        var statusReports = FakeMetadataBlobPayloadJsonFactory.GetEntry(payload)["statusReports"]?.AsArray() ?? throw new InvalidOperationException("No status reports");
        statusReports.Add(new JsonObject
        {
            ["status"] = status,
            ["effectiveDate"] = "2026-10-01"
        });
    }

    private static MetadataBlobPayload CreateBlob(params MetadataBlobPayloadEntry[] entries)
    {
        return new(null, 1, null, entries);
    }

    private static StatusReport CreateStatusReport(AuthenticatorStatus status)
    {
        return new(status, null, null, null, null, null, null, null, null, null, null, null, null, null);
    }

    private static byte[] CreateRootCertificate()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=WebAuthn.Net Test Root", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var certificate = request.CreateSelfSigned(CurrentDate.AddDays(-1), CurrentDate.AddDays(1));
        return certificate.Export(X509ContentType.Cert);
    }

    // a custom storage that always reports the given error
    private sealed class FailingSearchStorage : IFidoMetadataSearchStorage<FakeWebAuthnContext>
    {
        private readonly FidoMetadataSearchStorageError _error;

        public FailingSearchStorage(FidoMetadataSearchStorageError error)
        {
            _error = error;
        }

        public Task<Result<MetadataBlobPayloadEntry, FidoMetadataSearchStorageError>> FindByAaguidAsync(FakeWebAuthnContext context, Guid aaguid, CancellationToken cancellationToken)
        {
            return Task.FromResult(Result<MetadataBlobPayloadEntry, FidoMetadataSearchStorageError>.Fail(_error));
        }

        public Task<Result<MetadataBlobPayloadEntry, FidoMetadataSearchStorageError>> FindBySubjectKeyIdentifierAsync(FakeWebAuthnContext context, byte[] subjectKeyIdentifier, CancellationToken cancellationToken)
        {
            return Task.FromResult(Result<MetadataBlobPayloadEntry, FidoMetadataSearchStorageError>.Fail(_error));
        }
    }
}
