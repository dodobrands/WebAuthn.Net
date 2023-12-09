using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

namespace WebAuthn.Net.Services.FidoMetadata;

/// <summary>
///     The ingestion service for metadata obtained from the FIDO Metadata Service, designed to store data from the retrieved blob.
/// </summary>
public interface IFidoMetadataIngestService
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
