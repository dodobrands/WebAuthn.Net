using System;

namespace WebAuthn.Net.Configuration.Options;

/// <summary>
///     Options that define behavior when working with FIDO Metadata Service.
/// </summary>
public class FidoMetadataOptions
{
    /// <summary>
    ///     The address from where to download the FIDO Metadata Service metadata blob in the 3rd version format.
    /// </summary>
    public Uri Mds3BlobUri { get; set; } = new("https://mds3.fidoalliance.org", UriKind.Absolute);

    /// <summary>
    ///     The maximum size of the response body (the blob) in bytes that the client agrees to download from <see cref="Mds3BlobUri" />. The default is 64 MiB (67108864 bytes).
    /// </summary>
    /// <remarks>
    ///     The download is aborted as soon as the body exceeds this size, regardless of the 'Content-Length' header, to protect the application from a hostile or compromised endpoint.
    ///     For comparison, the blob published by the FIDO Alliance in October 2026 (no: 291) is about 10.6 MB.
    /// </remarks>
    public long MaxResponseSizeInBytes { get; set; } = 64L * 1024 * 1024;

    /// <summary>
    ///     The time limit for the whole download of the blob from <see cref="Mds3BlobUri" />: from sending the request to reading the last byte of the response body. The default is 5 minutes.
    /// </summary>
    /// <remarks>
    ///     The default is enough to download the current blob (about 10.6 MB) even over a slow connection (about 300 kbit/s),
    ///     while a hostile endpoint that sends the body slowly can't make the download (and the start of the application, which awaits the first download unless the blob embedded in the application is loaded) hang indefinitely.
    ///     <see cref="System.Net.Http.HttpClient.Timeout" /> doesn't replace it: it covers only the time until the response headers are received, because the body is read as a stream.
    /// </remarks>
    public TimeSpan DownloadTimeout { get; set; } = TimeSpan.FromMinutes(5);
}
