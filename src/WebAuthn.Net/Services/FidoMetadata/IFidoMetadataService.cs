using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService;

namespace WebAuthn.Net.Services.FidoMetadata;

public interface IFidoMetadataService<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<Optional<FidoMetadataResult>> FindMetadataByAaguidAsync(
        TContext context,
        Guid aaguid,
        CancellationToken cancellationToken);

    Task<Optional<FidoMetadataResult>> FindMetadataBySubjectKeyIdentifierAsync(
        TContext context,
        byte[] subjectKeyIdentifier,
        CancellationToken cancellationToken);

    Task UpsertAsync(
        MetadataBlobPayload metadataBlob,
        CancellationToken cancellationToken);
}
