using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

namespace WebAuthn.Net.Storage.FidoMetadata;

/// <summary>
///     The storage intended for searching in metadata obtained from the FIDO Metadata Service.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public interface IFidoMetadataSearchStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     Searches for a metadata entry by aaguid.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>An instance of <see cref="MetadataBlobPayloadEntry" /> if the entry is found, otherwise - <see langword="null" />.</returns>
    Task<MetadataBlobPayloadEntry?> FindByAaguidAsync(
        TContext context,
        Guid aaguid,
        CancellationToken cancellationToken);

    /// <summary>
    ///     Searches for a metadata entry by the subject key identifier.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="subjectKeyIdentifier">Subject key identifier.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>An instance of <see cref="MetadataBlobPayloadEntry" /> if the entry is found, otherwise - <see langword="null" />.</returns>
    Task<MetadataBlobPayloadEntry?> FindBySubjectKeyIdentifierAsync(
        TContext context,
        byte[] subjectKeyIdentifier,
        CancellationToken cancellationToken);

    /// <summary>
    ///     Reports whether the storage contains metadata to search in, that is, whether a blob obtained from the FIDO Metadata Service has been ingested.
    /// </summary>
    /// <remarks>
    ///     The search service calls this method when an entry is not found, to distinguish an authenticator that is absent from the metadata from the absence of the metadata itself
    ///     (for example, before the first successful ingestion), and reports the latter. The default implementation returns <see langword="true" />,
    ///     because a storage that doesn't track the ingestion can't tell these cases apart.
    /// </remarks>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns><see langword="true" /> if the storage contains metadata (or doesn't track its presence), otherwise - <see langword="false" />.</returns>
    Task<bool> IsMetadataAvailableAsync(
        TContext context,
        CancellationToken cancellationToken)
    {
        return Task.FromResult(true);
    }
}
