using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

namespace WebAuthn.Net.Storage.Operations.Implementation;

public class DefaultInMemoryFidoMetadataStorage : IFidoMetadataStorage
{
    protected MetadataBlobPayload? Blob { get; set; }

    public virtual Task StoreAsync(MetadataBlobPayload blob, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Blob = blob;
        return Task.CompletedTask;
    }

    public virtual Task<MetadataBlobPayloadEntry?> FindByAaguidAsync(
        Guid aaguid,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var currentBlob = Blob;
        if (currentBlob is null)
        {
            return Task.FromResult<MetadataBlobPayloadEntry?>(null);
        }

        var entry = currentBlob.Entries.FirstOrDefault(x => x.Aaguid == aaguid);
        return Task.FromResult(entry);
    }

    public Task<MetadataBlobPayloadEntry?> FindBySubjectKeyIdentifierAsync(
        byte[] subjectKeyIdentifier,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var currentBlob = Blob;
        if (currentBlob is null)
        {
            return Task.FromResult<MetadataBlobPayloadEntry?>(null);
        }

        var entry = currentBlob.Entries.FirstOrDefault(x =>
            x.AttestationCertificateKeyIdentifiers is not null
            && x.AttestationCertificateKeyIdentifiers.Any(y => y.AsSpan().SequenceEqual(subjectKeyIdentifier.AsSpan())));
        return Task.FromResult(entry);
    }
}
