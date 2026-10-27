using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

namespace WebAuthn.Net.Services.FidoMetadata;

/// <summary>
///     Provider of metadata from FIDO Metadata Service.
/// </summary>
public interface IFidoMetadataProvider
{
    /// <summary>
    ///     Asynchronously downloads and validates metadata from FIDO Metadata Service
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>If the download and validation were successful - the result contains <see cref="MetadataBLOBPayloadJSON" />, otherwise the result indicates that an error occurred during the download or validation.</returns>
    Task<Result<MetadataBLOBPayloadJSON>> DownloadMetadataAsync(CancellationToken cancellationToken);

    /// <summary>
    ///     Asynchronously loads and validates the FIDO Metadata Service blob embedded in the application as a manifest resource of an assembly.
    /// </summary>
    /// <remarks>
    ///     The default implementation of this interface method throws <see cref="NotSupportedException" />, so a provider that implements this interface from scratch
    ///     (rather than deriving from the default implementation) has to implement this method to support the blob embedded in the application.
    /// </remarks>
    /// <param name="embeddedBlob">The blob embedded in the application: the assembly and the name of its manifest resource that contains the blob exactly as the FIDO Metadata Service serves it (a JWS in the compact serialization).</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>If the loading and validation were successful - the result contains <see cref="MetadataBLOBPayloadJSON" />, otherwise the result indicates that an error occurred during the loading or validation.</returns>
    /// <exception cref="NotSupportedException">The provider doesn't support the blob embedded in the application.</exception>
    Task<Result<MetadataBLOBPayloadJSON>> LoadEmbeddedMetadataAsync(FidoMetadataEmbeddedBlob embeddedBlob, CancellationToken cancellationToken)
    {
        throw new NotSupportedException($"{GetType().FullName} doesn't support loading the FIDO Metadata Service blob embedded in the application");
    }
}
