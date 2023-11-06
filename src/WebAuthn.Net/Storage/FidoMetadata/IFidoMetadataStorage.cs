using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

namespace WebAuthn.Net.Storage.FidoMetadata;

public interface IFidoMetadataStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    Task StoreAsync(
        TContext context,
        MetadataBlobPayload blob,
        CancellationToken cancellationToken);

    Task<MetadataBlobPayloadEntry?> FindByAaguidAsync(
        TContext context,
        Guid aaguid,
        CancellationToken cancellationToken);

    Task<MetadataBlobPayloadEntry?> FindBySubjectKeyIdentifierAsync(
        TContext context,
        byte[] subjectKeyIdentifier,
        CancellationToken cancellationToken);
}
