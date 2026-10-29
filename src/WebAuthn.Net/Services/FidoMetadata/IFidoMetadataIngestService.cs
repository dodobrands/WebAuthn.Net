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

    /// <summary>
    ///     Upserts the data of the blob embedded in the application, which is loaded at start-up before the blob from the FIDO Metadata Service.
    /// </summary>
    /// <remarks>
    ///     The embedded blob is a fallback for the case when the FIDO Metadata Service is unavailable, so it is expected to be older than the metadata in use, if there is any
    ///     (for example, a persistent storage keeps the blob downloaded before the restart of the application). The default implementation of this interface method upserts it the same way as <see cref="UpsertAsync" />.
    /// </remarks>
    /// <param name="metadataBlob">A blob with metadata.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    Task UpsertEmbeddedAsync(
        MetadataBlobPayload metadataBlob,
        CancellationToken cancellationToken)
    {
        return UpsertAsync(metadataBlob, cancellationToken);
    }
}
