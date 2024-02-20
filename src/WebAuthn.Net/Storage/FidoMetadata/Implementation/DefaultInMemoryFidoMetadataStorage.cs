using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

namespace WebAuthn.Net.Storage.FidoMetadata.Implementation;

/// <summary>
///     The default in-memory implementation of storage for metadata obtained from the FIDO Metadata Service.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public class DefaultInMemoryFidoMetadataStorage<TContext> :
    IFidoMetadataSearchStorage<TContext>,
    IFidoMetadataIngestStorage
    where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     The current valid blob with metadata.
    /// </summary>
    protected MetadataBlobPayload? Blob { get; set; }

    /// <inheritdoc />
    public virtual Task UpsertAsync(MetadataBlobPayload metadataBlob, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Blob = metadataBlob;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public virtual Task<MetadataBlobPayloadEntry?> FindByAaguidAsync(
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

    /// <inheritdoc />
    public virtual Task<MetadataBlobPayloadEntry?> FindBySubjectKeyIdentifierAsync(
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
}
