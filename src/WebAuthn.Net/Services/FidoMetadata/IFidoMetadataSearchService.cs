using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService;

namespace WebAuthn.Net.Services.FidoMetadata;

/// <summary>
///     A service for searching in the data provided by the FIDO Metadata Service.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public interface IFidoMetadataSearchService<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<FidoMetadataResult?> FindMetadataByAaguidAsync(
        TContext context,
        Guid aaguid,
        CancellationToken cancellationToken);

    Task<FidoMetadataResult?> FindMetadataBySubjectKeyIdentifierAsync(
        TContext context,
        byte[] subjectKeyIdentifier,
        CancellationToken cancellationToken);
}
