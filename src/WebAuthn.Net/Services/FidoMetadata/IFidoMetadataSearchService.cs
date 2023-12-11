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
    /// <summary>
    ///     Searches for a metadata entry by aaguid.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>An instance of <see cref="FidoMetadataResult" /> if the entry is found, otherwise - <see langword="null" />.</returns>
    Task<FidoMetadataResult?> FindMetadataByAaguidAsync(
        TContext context,
        Guid aaguid,
        CancellationToken cancellationToken);

    /// <summary>
    ///     Searches for a metadata entry by the subject key identifier.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="subjectKeyIdentifier">Subject key identifier.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>An instance of <see cref="FidoMetadataResult" /> if the entry is found, otherwise - <see langword="null" />.</returns>
    Task<FidoMetadataResult?> FindMetadataBySubjectKeyIdentifierAsync(
        TContext context,
        byte[] subjectKeyIdentifier,
        CancellationToken cancellationToken);
}
