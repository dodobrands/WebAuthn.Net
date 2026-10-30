using System;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider.Constants;

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

    /// <summary>
    ///     The DNS name to which the certificate that signs the blob (the first certificate in the 'x5c' member of the JWT header) has to be issued.
    ///     The default is <c>mds.fidoalliance.org</c>, the name in the certificate with which the FIDO Metadata Service signs its blobs.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         The certificate chain of the blob ends at the root certificate of the FIDO Metadata Service embedded in the library (GlobalSign Root R46).
    ///         The chain shows who issued the signing certificate, but not to whom. Therefore the signing certificate also has to contain this DNS name in its Subject Alternative Name extension
    ///         (an exact match: neither a wildcard name nor the common name of the subject is considered), and its Extended Key Usage extension has to allow TLS server authentication (<c>id-kp-serverAuth</c>),
    ///         as in the certificate of the FIDO Metadata Service. Otherwise the blob is rejected, logged and counted (<see cref="FidoMetadataDownloadFailures.SignerInvalid" />).
    ///         This applies both to the blobs downloaded from <see cref="Mds3BlobUri" /> and to the blob embedded in the application.
    ///     </para>
    ///     <para>
    ///         <see langword="null" /> turns the check off, so that any certificate that chains up to the root certificates can sign the blob. This is meant only for a test environment that signs its blobs
    ///         under its own root certificates, for example, the MDS3 test server of the FIDO Conformance Tools. An invalid DNS name (for example, an empty string or a wildcard name)
    ///         makes <see cref="DefaultFidoMetadataProvider" /> throw <see cref="ArgumentException" /> for every blob.
    ///     </para>
    /// </remarks>
    public string? SigningCertificateDnsName { get; set; } = "mds.fidoalliance.org";
}
