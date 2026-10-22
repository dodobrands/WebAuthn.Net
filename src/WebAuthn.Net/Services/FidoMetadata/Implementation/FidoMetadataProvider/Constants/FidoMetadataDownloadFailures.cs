namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider.Constants;

/// <summary>
///     The reasons why <see cref="DefaultFidoMetadataProvider" /> doesn't provide the FIDO Metadata Service blob. Each of them is reported with a Warning log entry and the
///     <c>webauthn.mds.download.failures</c> counter (<see cref="Metrics.IFidoMetadataCounters.IncrementDownloadFailure" />, tag <c>reason</c>).
/// </summary>
/// <remarks>
///     A blob that is not provided leaves the metadata in use unchanged, so a persisting failure means that the statuses of the authenticators are not updated:
///     <see cref="RootCertificatesInvalid" /> means that the library has to be updated, the other reasons point to the network, the FIDO Metadata Service or the data it served.
/// </remarks>
public static class FidoMetadataDownloadFailures
{
    /// <summary>
    ///     The blob could not be downloaded: the connection could not be established or was broken, the response has an unsuccessful status code,
    ///     or the response exceeds the limits of the HTTP client (<see cref="IFidoMetadataHttpClient" />).
    /// </summary>
    public const string RequestFailed = "request_failed";

    /// <summary>
    ///     The blob could not be downloaded within the timeout of the HTTP client (<see cref="IFidoMetadataHttpClient" />).
    /// </summary>
    public const string Timeout = "timeout";

    /// <summary>
    ///     The downloaded data is not a JWS (JWT) in the compact serialization (for example, an error page returned with a successful status code).
    /// </summary>
    public const string JwtMalformed = "jwt_malformed";

    /// <summary>
    ///     The 'x5c' member of the JWT header is missing or invalid: one of its certificates can't be loaded or is not valid at the current time,
    ///     or the signing certificate (the first one) contains neither an ECDSA nor an RSA public key.
    /// </summary>
    public const string X5CInvalid = "x5c_invalid";

    /// <summary>
    ///     None of the root certificates of the FIDO Metadata Service embedded in the library can be used: there are none, one of them can't be loaded,
    ///     or none of them is valid at the current time.
    /// </summary>
    public const string RootCertificatesInvalid = "root_certificates_invalid";

    /// <summary>
    ///     The signing certificate chain of the blob is invalid: it can't be built from the signing certificate to one of the root certificates,
    ///     or it doesn't satisfy the chain policy (<see cref="Configuration.Options.X509ChainValidationOptions.OnValidateFidoMetadataBlobJwtChain" />).
    /// </summary>
    public const string ChainInvalid = "chain_invalid";

    /// <summary>
    ///     The signing certificate chain of the blob was rejected by the additional validation (<see cref="DefaultFidoMetadataProvider.ValidateJwtCertificateChainAsync" />).
    /// </summary>
    public const string ChainRejected = "chain_rejected";

    /// <summary>
    ///     The signature of the JWT is not valid for the key of the signing certificate (the first certificate in the 'x5c' member), or its algorithm is not acceptable.
    /// </summary>
    public const string SignatureInvalid = "signature_invalid";

    /// <summary>
    ///     The payload of the JWT is not a valid base64url string, or it can't be deserialized into a MetadataBLOBPayloadJSON.
    /// </summary>
    public const string PayloadInvalid = "payload_invalid";
}
