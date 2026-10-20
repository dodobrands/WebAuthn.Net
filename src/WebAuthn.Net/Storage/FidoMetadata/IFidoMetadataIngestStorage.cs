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

    /// <summary>
    ///     Returns the serial number (the <c>no</c> member) of the blob that is currently stored.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         The ingestion service uses the returned value to protect the metadata from a rollback: a blob whose serial number is lower than the serial number of the stored blob
    ///         is not upserted, because the serial numbers
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-mds-payload-blob">MUST be consecutive and strictly monotonic</a>.
    ///     </para>
    ///     <para>
    ///         The default implementation returns <see langword="null" />, which means that the storage doesn't track the serial number of the stored blob. In this case the ingestion service
    ///         protects the metadata from a rollback only within its own lifetime. A persistent storage should override this method so that the protection also covers the restarts of the application.
    ///     </para>
    /// </remarks>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>The serial number of the stored blob, or <see langword="null" /> if no blob is stored or the storage doesn't track its serial number.</returns>
    Task<long?> GetCurrentBlobNoAsync(CancellationToken cancellationToken)
    {
        return Task.FromResult<long?>(null);
    }
}
