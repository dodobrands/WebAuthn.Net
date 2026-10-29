using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataIngestService;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Storage.FidoMetadata;
using WebAuthn.Net.Storage.FidoMetadata.Implementation;
using WebAuthn.Net.Storage.FidoMetadata.Models.Enums;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

public class DefaultFidoMetadataIngestServiceTests
{
    private static readonly Guid FirstAaguid = Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid);
    private static readonly Guid SecondAaguid = Guid.Parse(FakeMetadataBlobPayloadJsonFactory.SecondAaguid);

    private FakeFidoMetadataCounters Counters { get; set; } = null!;
    private FakeLogger<DefaultFidoMetadataIngestService> Logger { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        Counters = new();
        Logger = new();
    }

    [Test]
    public async Task DefaultFidoMetadataIngestService_UpsertAsync_WhenBlobNoIsLower_RejectsBlobAndKeepsCurrentOne()
    {
        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-mds-payload-blob
        // Serial numbers MUST be consecutive and strictly monotonic, so a correctly signed but older blob must not replace the blob in use:
        // it could silently restore the trust in an authenticator that has been revoked since then.
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        var ingestService = new DefaultFidoMetadataIngestService(storage, Counters, Logger);
        await using var context = new FakeWebAuthnContext(null, new());
        await ingestService.UpsertAsync(CreateBlob(2, FirstAaguid, SecondAaguid), CancellationToken.None);

        await ingestService.UpsertAsync(CreateBlob(1, FirstAaguid), CancellationToken.None);

        Assert.That(await storage.GetCurrentBlobNoAsync(CancellationToken.None), Is.EqualTo(2));
        Assert.That((await storage.FindByAaguidAsync(context, SecondAaguid, CancellationToken.None)).HasError, Is.False);
        Assert.That(Counters.BlobsRejectedDueToRollback, Is.EqualTo(1));
        var warnings = Logger.Entries.Where(static x => x.Level == LogLevel.Warning).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(1));
        Assert.That(warnings[0].Message, Does.Contain("(no: 1)").And.Contain("(no: 2)"));
    }

    [Test]
    public async Task DefaultFidoMetadataIngestService_UpsertAsync_WhenBlobNoIsEqual_AcceptsBlob()
    {
        // The FIDO Metadata Service publishes the same blob until the next update, so the blob downloaded again (with the same serial number) is accepted.
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        var ingestService = new DefaultFidoMetadataIngestService(storage, Counters, Logger);
        await using var context = new FakeWebAuthnContext(null, new());
        await ingestService.UpsertAsync(CreateBlob(2, FirstAaguid), CancellationToken.None);

        await ingestService.UpsertAsync(CreateBlob(2, FirstAaguid, SecondAaguid), CancellationToken.None);

        Assert.That(await storage.GetCurrentBlobNoAsync(CancellationToken.None), Is.EqualTo(2));
        Assert.That((await storage.FindByAaguidAsync(context, SecondAaguid, CancellationToken.None)).HasError, Is.False);
        Assert.That(Counters.BlobsRejectedDueToRollback, Is.EqualTo(0));
        Assert.That(Logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
    }

    [Test]
    public async Task DefaultFidoMetadataIngestService_UpsertAsync_WhenBlobNoIsGreater_AcceptsBlob()
    {
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        var ingestService = new DefaultFidoMetadataIngestService(storage, Counters, Logger);
        await using var context = new FakeWebAuthnContext(null, new());
        await ingestService.UpsertAsync(CreateBlob(1, FirstAaguid), CancellationToken.None);

        await ingestService.UpsertAsync(CreateBlob(2, SecondAaguid), CancellationToken.None);

        Assert.That(await storage.GetCurrentBlobNoAsync(CancellationToken.None), Is.EqualTo(2));
        Assert.That((await storage.FindByAaguidAsync(context, FirstAaguid, CancellationToken.None)).Error, Is.EqualTo(FidoMetadataSearchStorageError.NotFound));
        Assert.That((await storage.FindByAaguidAsync(context, SecondAaguid, CancellationToken.None)).HasError, Is.False);
        Assert.That(Counters.BlobsRejectedDueToRollback, Is.EqualTo(0));
        Assert.That(Logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
        Assert.That(Logger.Entries.Where(static x => x.Level == LogLevel.Information).Select(static x => x.Message), Has.Some.Contains("(no: 2)"));
    }

    [Test]
    public async Task DefaultFidoMetadataIngestService_UpsertAsync_WhenStorageDoesNotTrackBlobNo_RejectsRollbackWithinInstance()
    {
        // A storage that doesn't override IFidoMetadataIngestStorage.GetCurrentBlobNoAsync can't report the serial number of the stored blob,
        // so the service protects the metadata with the serial number of the last blob it has accepted itself.
        var storage = new UpsertOnlyIngestStorage();
        var ingestService = new DefaultFidoMetadataIngestService(storage, Counters, Logger);
        await ingestService.UpsertAsync(CreateBlob(2, FirstAaguid, SecondAaguid), CancellationToken.None);

        await ingestService.UpsertAsync(CreateBlob(1, FirstAaguid), CancellationToken.None);

        Assert.That(storage.Upserts, Is.EqualTo(1));
        Assert.That(storage.LastUpserted?.No, Is.EqualTo(2));
        Assert.That(Counters.BlobsRejectedDueToRollback, Is.EqualTo(1));
        Assert.That(Logger.Entries.Where(static x => x.Level == LogLevel.Warning), Has.Exactly(1).Items);
    }

    [Test]
    public async Task DefaultFidoMetadataIngestService_UpsertAsync_WhenStorageTracksBlobNo_RejectsRollbackBeforeFirstAcceptInInstance()
    {
        // Simulates a persistent storage that still contains the blob no=5 from a previous run of the application:
        // the protection must work from the first upsert of the new instance, before it has accepted anything itself.
        var storage = new BlobNoTrackingIngestStorage(5);
        var ingestService = new DefaultFidoMetadataIngestService(storage, Counters, Logger);

        await ingestService.UpsertAsync(CreateBlob(4, FirstAaguid), CancellationToken.None);
        Assert.That(storage.Upserts, Is.EqualTo(0));
        Assert.That(Counters.BlobsRejectedDueToRollback, Is.EqualTo(1));

        await ingestService.UpsertAsync(CreateBlob(5, FirstAaguid), CancellationToken.None);
        Assert.That(storage.Upserts, Is.EqualTo(1));

        await ingestService.UpsertAsync(CreateBlob(6, FirstAaguid), CancellationToken.None);
        Assert.That(storage.Upserts, Is.EqualTo(2));
        Assert.That(storage.CurrentBlobNo, Is.EqualTo(6));
        Assert.That(Counters.BlobsRejectedDueToRollback, Is.EqualTo(1));
    }

    [Test]
    public async Task DefaultFidoMetadataIngestService_UpsertAsync_WhenCanReplaceCurrentBlobIsOverridden_AppliesCustomPolicy()
    {
        // The policy is a protected virtual hook; this one requires a strictly greater serial number, so the same blob is rejected.
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        var ingestService = new StrictlyMonotonicIngestService(storage, Counters, Logger);
        await ingestService.UpsertAsync(CreateBlob(2, FirstAaguid), CancellationToken.None);

        await ingestService.UpsertAsync(CreateBlob(2, FirstAaguid, SecondAaguid), CancellationToken.None);
        await ingestService.UpsertAsync(CreateBlob(3, FirstAaguid, SecondAaguid), CancellationToken.None);

        Assert.That(await storage.GetCurrentBlobNoAsync(CancellationToken.None), Is.EqualTo(3));
        Assert.That(Counters.BlobsRejectedDueToRollback, Is.EqualTo(1));
    }

    [Test]
    public async Task DefaultFidoMetadataIngestService_UpsertAsync_WhenConstructedWithoutCountersAndLogger_StillRejectsRollback()
    {
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        var ingestService = new DefaultFidoMetadataIngestService(storage);
        await ingestService.UpsertAsync(CreateBlob(2, FirstAaguid), CancellationToken.None);

        await ingestService.UpsertAsync(CreateBlob(1, FirstAaguid), CancellationToken.None);

        Assert.That(await storage.GetCurrentBlobNoAsync(CancellationToken.None), Is.EqualTo(2));
    }

    [Test]
    public async Task DefaultFidoMetadataIngestService_UpsertAsync_WhenResolvedFromDependencyInjection_ReportsRejectedBlobs()
    {
        // The container must pick the constructor with the counters and the logger (there are two constructors), otherwise the rejected blobs would be reported nowhere.
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IFidoMetadataIngestStorage>(storage);
        services.AddSingleton<IFidoMetadataCounters>(Counters);
        services.AddSingleton<ILogger<DefaultFidoMetadataIngestService>>(Logger);
        services.TryAddSingleton<IFidoMetadataIngestService, DefaultFidoMetadataIngestService>();
        await using var serviceProvider = services.BuildServiceProvider();
        var ingestService = serviceProvider.GetRequiredService<IFidoMetadataIngestService>();
        await ingestService.UpsertAsync(CreateBlob(2, FirstAaguid), CancellationToken.None);

        await ingestService.UpsertAsync(CreateBlob(1, FirstAaguid), CancellationToken.None);

        Assert.That(ingestService, Is.InstanceOf<DefaultFidoMetadataIngestService>());
        Assert.That(await storage.GetCurrentBlobNoAsync(CancellationToken.None), Is.EqualTo(2));
        Assert.That(Counters.BlobsRejectedDueToRollback, Is.EqualTo(1));
        Assert.That(Logger.Entries.Where(static x => x.Level == LogLevel.Warning), Has.Exactly(1).Items);
    }

    [Test]
    public async Task DefaultFidoMetadataIngestService_UpsertEmbeddedAsync_WhenNoBlobIsInUse_AcceptsBlob()
    {
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        var ingestService = new DefaultFidoMetadataIngestService(storage, Counters, Logger);

        await ingestService.UpsertEmbeddedAsync(CreateBlob(291, FirstAaguid), CancellationToken.None);

        Assert.That(await storage.GetCurrentBlobNoAsync(CancellationToken.None), Is.EqualTo(291));
        Assert.That(Logger.Entries.Single(static x => x.Level == LogLevel.Information).Message, Does.Contain("(no: 291) with 1 entries embedded in the application was ingested"));
    }

    [TestCase(300)]
    [TestCase(291)]
    public async Task DefaultFidoMetadataIngestService_UpsertEmbeddedAsync_WhenBlobInUseIsNotOlder_KeepsItWithoutReportingRollback(long currentNo)
    {
        // A persistent storage keeps the blob downloaded before the restart of the application, so an older embedded blob is expected: it is not a rollback.
        var storage = new BlobNoTrackingIngestStorage(currentNo);
        var ingestService = new DefaultFidoMetadataIngestService(storage, Counters, Logger);

        await ingestService.UpsertEmbeddedAsync(CreateBlob(291, FirstAaguid), CancellationToken.None);

        Assert.That(storage.Upserts, Is.Zero);
        Assert.That(storage.CurrentBlobNo, Is.EqualTo(currentNo));
        Assert.That(Counters.BlobsRejectedDueToRollback, Is.Zero);
        Assert.That(Logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
        Assert.That(Logger.Entries.Single(static x => x.Level == LogLevel.Information).Message, Does.Contain($"(no: 291) embedded in the application was not ingested because the metadata in use (no: {currentNo}) is not older"));
    }

    [Test]
    public async Task DefaultFidoMetadataIngestService_UpsertEmbeddedAsync_WhenBlobInUseIsOlder_AcceptsBlob()
    {
        var storage = new BlobNoTrackingIngestStorage(285);
        var ingestService = new DefaultFidoMetadataIngestService(storage, Counters, Logger);

        await ingestService.UpsertEmbeddedAsync(CreateBlob(291, FirstAaguid), CancellationToken.None);

        Assert.That(storage.Upserts, Is.EqualTo(1));
        Assert.That(storage.CurrentBlobNo, Is.EqualTo(291));
    }

    [Test]
    public async Task DefaultFidoMetadataIngestService_UpsertAsync_AfterEmbeddedBlob_RejectsOlderBlobFromFidoMetadataService()
    {
        // The embedded blob is a blob in use like any other, so a blob served by the FIDO Metadata Service must not roll it back.
        var storage = new UpsertOnlyIngestStorage();
        var ingestService = new DefaultFidoMetadataIngestService(storage, Counters, Logger);
        await ingestService.UpsertEmbeddedAsync(CreateBlob(291, FirstAaguid), CancellationToken.None);

        await ingestService.UpsertAsync(CreateBlob(290, FirstAaguid), CancellationToken.None);
        await ingestService.UpsertAsync(CreateBlob(292, FirstAaguid), CancellationToken.None);

        Assert.That(storage.Upserts, Is.EqualTo(2));
        Assert.That(storage.LastUpserted?.No, Is.EqualTo(292));
        Assert.That(Counters.BlobsRejectedDueToRollback, Is.EqualTo(1));
    }

    [Test]
    public async Task IFidoMetadataIngestService_UpsertEmbeddedAsync_ByDefault_UpsertsLikeUpsertAsync()
    {
        // An ingestion service implemented from scratch keeps compiling: the default interface method passes the embedded blob to UpsertAsync.
        IFidoMetadataIngestService ingestService = new RecordingIngestService();

        await ingestService.UpsertEmbeddedAsync(CreateBlob(291, FirstAaguid), CancellationToken.None);

        Assert.That(((RecordingIngestService) ingestService).Upserted.Select(static x => x.No).Single(), Is.EqualTo(291));
    }

    private static MetadataBlobPayload CreateBlob(long no, params Guid[] aaguids)
    {
        var entries = aaguids
            .Select(static aaguid => new MetadataBlobPayloadEntry(
                null,
                aaguid,
                null,
                null,
                null,
                Array.Empty<StatusReport>(),
                DateTimeOffset.UnixEpoch,
                null,
                null))
            .ToArray();
        return new(null, no, null, entries);
    }

    private sealed class UpsertOnlyIngestStorage : IFidoMetadataIngestStorage
    {
        public int Upserts { get; private set; }

        public MetadataBlobPayload? LastUpserted { get; private set; }

        public Task UpsertAsync(MetadataBlobPayload metadataBlob, CancellationToken cancellationToken)
        {
            Upserts++;
            LastUpserted = metadataBlob;
            return Task.CompletedTask;
        }
    }

    private sealed class BlobNoTrackingIngestStorage : IFidoMetadataIngestStorage
    {
        public BlobNoTrackingIngestStorage(long? currentBlobNo)
        {
            CurrentBlobNo = currentBlobNo;
        }

        public long? CurrentBlobNo { get; private set; }

        public int Upserts { get; private set; }

        public Task UpsertAsync(MetadataBlobPayload metadataBlob, CancellationToken cancellationToken)
        {
            Upserts++;
            CurrentBlobNo = metadataBlob.No;
            return Task.CompletedTask;
        }

        public Task<long?> GetCurrentBlobNoAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(CurrentBlobNo);
        }
    }

    private sealed class RecordingIngestService : IFidoMetadataIngestService
    {
        private readonly List<MetadataBlobPayload> _upserted = new();

        public IReadOnlyList<MetadataBlobPayload> Upserted => _upserted;

        public Task UpsertAsync(MetadataBlobPayload metadataBlob, CancellationToken cancellationToken)
        {
            _upserted.Add(metadataBlob);
            return Task.CompletedTask;
        }
    }

    private sealed class StrictlyMonotonicIngestService : DefaultFidoMetadataIngestService
    {
        public StrictlyMonotonicIngestService(
            IFidoMetadataIngestStorage metadataIngestStorage,
            IFidoMetadataCounters counters,
            ILogger<DefaultFidoMetadataIngestService> logger)
            : base(metadataIngestStorage, counters, logger)
        {
        }

        protected override bool CanReplaceCurrentBlob(long currentNo, MetadataBlobPayload metadataBlob)
        {
            return metadataBlob.No > currentNo;
        }
    }
}
