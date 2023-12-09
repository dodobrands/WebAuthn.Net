using System.Threading;
using System.Threading.Tasks;

namespace WebAuthn.Net.Services.FidoMetadata;

/// <summary>
///     An HTTP client for retrieving blob with metadata from the FIDO Metadata Service.
/// </summary>
public interface IFidoMetadataHttpClient
{
    /// <summary>
    ///     Downloads the blob with metadata and returns its content as a string.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>A string containing a blob with metadata in the form of a JWS (JWT) token.</returns>
    Task<string> DownloadMetadataAsync(CancellationToken cancellationToken);
}
