using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

namespace WebAuthn.Net.Storage.FidoMetadata;

/// <summary>
///     Storage designed for the ingestion of metadata obtained from the FIDO Metadata Service.
/// </summary>
public interface IFidoMetadataIngestStorage
{
    /// <summary>
    ///     Upserts the blob data.
    /// </summary>
    /// <param name="metadataBlob">A blob with metadata.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    Task UpsertAsync(
        MetadataBlobPayload metadataBlob,
        CancellationToken cancellationToken);
}
