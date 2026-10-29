using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataIngest;
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
    ///     <see cref="FidoMetadataIngestBackgroundService" /> calls this method only if <see cref="FidoMetadataIngestBackgroundServiceOptions.EmbeddedBlob" /> is set. A provider that doesn't support
    ///     the blob embedded in the application throws <see cref="NotSupportedException" />: the exception is logged and counted, and the metadata is loaded only from the FIDO Metadata Service.
    /// </remarks>
    /// <param name="assembly">The assembly that contains the blob as a manifest resource.</param>
    /// <param name="resourceName">The name of the manifest resource that contains the blob exactly as the FIDO Metadata Service serves it (a JWS in the compact serialization).</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>If the loading and validation were successful - the result contains <see cref="MetadataBLOBPayloadJSON" />, otherwise the result indicates that an error occurred during the loading or validation.</returns>
    /// <exception cref="NotSupportedException">The provider doesn't support the blob embedded in the application.</exception>
    Task<Result<MetadataBLOBPayloadJSON>> LoadEmbeddedMetadataAsync(Assembly assembly, string resourceName, CancellationToken cancellationToken);
}
