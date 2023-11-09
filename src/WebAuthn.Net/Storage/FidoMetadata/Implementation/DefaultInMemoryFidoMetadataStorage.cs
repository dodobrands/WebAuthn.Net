using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

namespace WebAuthn.Net.Storage.FidoMetadata.Implementation;

public class DefaultInMemoryFidoMetadataStorage<TContext> : IFidoMetadataStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    protected MetadataBlobPayload? Blob { get; set; }

    public Task<MetadataBlobPayloadEntry?> FindByAaguidAsync(
        TContext context,
        Guid aaguid,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var currentBlob = Blob;
        if (currentBlob is null)
        {
            throw new InvalidOperationException("Fido metadata blob doesn't exists");
        }

        var entry = currentBlob.Entries.FirstOrDefault(x => x.Aaguid == aaguid);
        return Task.FromResult(entry);
    }

    public Task<MetadataBlobPayloadEntry?> FindBySubjectKeyIdentifierAsync(
        TContext context,
        byte[] subjectKeyIdentifier,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var currentBlob = Blob;
        if (currentBlob is null)
        {
            throw new InvalidOperationException("Fido metadata blob doesn't exists");
        }

        var entry = currentBlob.Entries.FirstOrDefault(x =>
            x.AttestationCertificateKeyIdentifiers is not null
            && x.AttestationCertificateKeyIdentifiers.Any(y => y.AsSpan().SequenceEqual(subjectKeyIdentifier.AsSpan())));
        return Task.FromResult(entry);
    }

    public Task UpsertAsync(MetadataBlobPayload metadataBlob, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Blob = metadataBlob;
        return Task.CompletedTask;
    }
}
