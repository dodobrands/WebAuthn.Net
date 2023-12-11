using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
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
}
