using System;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Storage.FidoMetadata.Implementation;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

public class DefaultInMemoryFidoMetadataStorageTests
{
    private static readonly Guid Aaguid = Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid);
    private static readonly byte[] SubjectKeyIdentifier = { 0x01, 0x02, 0x03, 0x04 };

    [Test]
    public async Task DefaultInMemoryFidoMetadataStorage_FindByAaguidAsync_BeforeFirstUpsert_ReturnsNull()
    {
        // Before the first successful ingestion there is no blob; the lookup must report "not found" instead of throwing,
        // so that a registration with full attestation fails cleanly instead of faulting with an unhandled exception.
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        await using var context = new FakeWebAuthnContext(null, new());

        var entry = await storage.FindByAaguidAsync(context, Aaguid, CancellationToken.None);

        Assert.That(entry, Is.Null);
    }

    [Test]
    public async Task DefaultInMemoryFidoMetadataStorage_FindBySubjectKeyIdentifierAsync_BeforeFirstUpsert_ReturnsNull()
    {
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        await using var context = new FakeWebAuthnContext(null, new());

        var entry = await storage.FindBySubjectKeyIdentifierAsync(context, SubjectKeyIdentifier, CancellationToken.None);

        Assert.That(entry, Is.Null);
    }

    [Test]
    public async Task DefaultInMemoryFidoMetadataStorage_IsMetadataAvailableAsync_ReflectsWhetherBlobWasUpserted()
    {
        var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
        await using var context = new FakeWebAuthnContext(null, new());
        Assert.That(await storage.IsMetadataAvailableAsync(context, CancellationToken.None), Is.False);

        await storage.UpsertAsync(CreateBlob(7), CancellationToken.None);

        Assert.That(await storage.IsMetadataAvailableAsync(context, CancellationToken.None), Is.True);
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

        Assert.That(byAaguid?.Aaguid, Is.EqualTo(Aaguid));
        Assert.That(bySubjectKeyIdentifier?.AttestationCertificateKeyIdentifiers, Is.Not.Null);
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
