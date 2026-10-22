using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Storage.FidoMetadata.Models.Enums;

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
    /// <returns>
    ///     If the entry is found, the result contains <see cref="MetadataBlobPayloadEntry" />. Otherwise, the result contains the reason: <see cref="FidoMetadataSearchStorageError.NotFound" /> if the storage contains metadata,
    ///     but there is no entry for the <paramref name="aaguid" /> in it, or <see cref="FidoMetadataSearchStorageError.MetadataNotAvailable" /> if the storage contains no metadata at all (no blob has been ingested yet).
    /// </returns>
    Task<Result<MetadataBlobPayloadEntry, FidoMetadataSearchStorageError>> FindByAaguidAsync(
        TContext context,
        Guid aaguid,
        CancellationToken cancellationToken);

    /// <summary>
    ///     Searches for a metadata entry by the subject key identifier.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="subjectKeyIdentifier">Subject key identifier.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>
    ///     If the entry is found, the result contains <see cref="MetadataBlobPayloadEntry" />. Otherwise, the result contains the reason: <see cref="FidoMetadataSearchStorageError.NotFound" /> if the storage contains metadata,
    ///     but there is no entry for the <paramref name="subjectKeyIdentifier" /> in it, or <see cref="FidoMetadataSearchStorageError.MetadataNotAvailable" /> if the storage contains no metadata at all (no blob has been ingested yet).
    /// </returns>
    Task<Result<MetadataBlobPayloadEntry, FidoMetadataSearchStorageError>> FindBySubjectKeyIdentifierAsync(
        TContext context,
        byte[] subjectKeyIdentifier,
        CancellationToken cancellationToken);
}
