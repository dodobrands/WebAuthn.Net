using System;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Storage.FidoMetadata.Implementation;
using WebAuthn.Net.Storage.FidoMetadata.Models.Enums;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

public class DefaultInMemoryFidoMetadataStorageTests
{
    private static readonly Guid Aaguid = Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid);
    private static readonly byte[] SubjectKeyIdentifier = { 0x01, 0x02, 0x03, 0x04 };

    [Test]
    public async Task DefaultInMemoryFidoMetadataStorage_FindByAaguidAsync_BeforeFirstUpsert_ReturnsMetadataNotAvailable()
    {
        // Before the first successful ingestion there is no blob; the lookup must report the absence of the metadata instead of throwing,
        // so that a registration with full attestation fails cleanly instead of faulting with an unhandled exception.
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        await using var context = new FakeWebAuthnContext(null, new());

        var result = await storage.FindByAaguidAsync(context, Aaguid, CancellationToken.None);

        Assert.That(result.Error, Is.EqualTo(FidoMetadataSearchStorageError.MetadataNotAvailable));
    }

    [Test]
    public async Task DefaultInMemoryFidoMetadataStorage_FindBySubjectKeyIdentifierAsync_BeforeFirstUpsert_ReturnsMetadataNotAvailable()
    {
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        await using var context = new FakeWebAuthnContext(null, new());

        var result = await storage.FindBySubjectKeyIdentifierAsync(context, SubjectKeyIdentifier, CancellationToken.None);

        Assert.That(result.Error, Is.EqualTo(FidoMetadataSearchStorageError.MetadataNotAvailable));
    }

    [Test]
    public async Task DefaultInMemoryFidoMetadataStorage_FindAsync_AfterUpsert_ReturnsNotFoundForAbsentEntries()
    {
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        await using var context = new FakeWebAuthnContext(null, new());
        await storage.UpsertAsync(CreateBlob(7), CancellationToken.None);

        var byAaguid = await storage.FindByAaguidAsync(context, Guid.Parse(FakeMetadataBlobPayloadJsonFactory.SecondAaguid), CancellationToken.None);
        var bySubjectKeyIdentifier = await storage.FindBySubjectKeyIdentifierAsync(context, new byte[] { 0x05, 0x06, 0x07, 0x08 }, CancellationToken.None);

        Assert.That(byAaguid.Error, Is.EqualTo(FidoMetadataSearchStorageError.NotFound));
        Assert.That(bySubjectKeyIdentifier.Error, Is.EqualTo(FidoMetadataSearchStorageError.NotFound));
    }

    [Test]
    public async Task DefaultInMemoryFidoMetadataStorage_GetCurrentBlobNoAsync_ReflectsUpsertedBlob()
    {
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        Assert.That(await storage.GetCurrentBlobNoAsync(CancellationToken.None), Is.Null);

        await storage.UpsertAsync(CreateBlob(7), CancellationToken.None);

        Assert.That(await storage.GetCurrentBlobNoAsync(CancellationToken.None), Is.EqualTo(7));
    }

    [Test]
    public async Task DefaultInMemoryFidoMetadataStorage_FindAsync_AfterUpsert_FindsEntries()
    {
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        await using var context = new FakeWebAuthnContext(null, new());
        await storage.UpsertAsync(CreateBlob(7), CancellationToken.None);

        var byAaguid = await storage.FindByAaguidAsync(context, Aaguid, CancellationToken.None);
        var bySubjectKeyIdentifier = await storage.FindBySubjectKeyIdentifierAsync(context, SubjectKeyIdentifier, CancellationToken.None);

        Assert.That(byAaguid.Ok?.Aaguid, Is.EqualTo(Aaguid));
        Assert.That(bySubjectKeyIdentifier.Ok?.AttestationCertificateKeyIdentifiers, Is.Not.Null);
    }

    private static MetadataBlobPayload CreateBlob(long no)
    {
        var entries = new[]
        {
            new MetadataBlobPayloadEntry(null, Aaguid, null, null, null, Array.Empty<StatusReport>(), DateTimeOffset.UnixEpoch, null, null),
            new MetadataBlobPayloadEntry(null, null, new[] { SubjectKeyIdentifier }, null, null, Array.Empty<StatusReport>(), DateTimeOffset.UnixEpoch, null, null)
        };
        return new(null, no, null, entries);
    }
}
