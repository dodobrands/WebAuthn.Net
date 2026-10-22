using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService.Enums;

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
    /// <returns>
    ///     If a usable entry that allows to trust the authenticator is found, the result contains <see cref="FidoMetadataResult" />. Otherwise, the result contains the reason (<see cref="FidoMetadataSearchError" />):
    ///     there is no usable entry for the authenticator, or no metadata is available at all, or the entry doesn't allow to trust the authenticator, so that its attestation must be rejected.
    /// </returns>
    Task<Result<FidoMetadataResult, FidoMetadataSearchError>> FindMetadataByAaguidAsync(
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
    ///     If a usable entry that allows to trust the authenticator is found, the result contains <see cref="FidoMetadataResult" />. Otherwise, the result contains the reason (<see cref="FidoMetadataSearchError" />):
    ///     there is no usable entry for the authenticator, or no metadata is available at all, or the entry doesn't allow to trust the authenticator, so that its attestation must be rejected.
    /// </returns>
    Task<Result<FidoMetadataResult, FidoMetadataSearchError>> FindMetadataBySubjectKeyIdentifierAsync(
        TContext context,
        byte[] subjectKeyIdentifier,
        CancellationToken cancellationToken);
}
