namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider.Constants;

/// <summary>
///     The reasons why <see cref="DefaultFidoMetadataProvider" /> doesn't provide the FIDO Metadata Service blob embedded in the application. Each of them is reported with a Warning log entry and the
///     <c>webauthn.mds.embedded.failures</c> counter (<see cref="Metrics.IFidoMetadataCounters.IncrementEmbeddedLoadFailure" />, tag <c>reason</c>).
/// </summary>
/// <remarks>
///     A blob embedded in the application that is not provided is not used: the metadata is loaded only from the FIDO Metadata Service.
///     <see cref="ResourceNotFound" /> points to the configuration of the application, the other reasons point to the content of the resource
///     (they have the same values as the corresponding <see cref="FidoMetadataDownloadFailures" />).
/// </remarks>
public static class FidoMetadataEmbeddedBlobFailures
{
    /// <summary>
    ///     The assembly doesn't contain a manifest resource with the configured name.
    /// </summary>
    public const string ResourceNotFound = "resource_not_found";

    /// <summary>
    ///     The content of the resource is not a JWS (JWT) in the compact serialization.
    /// </summary>
    public const string JwtMalformed = FidoMetadataDownloadFailures.JwtMalformed;

    /// <summary>
    ///     The 'x5c' member of the JWT header is missing or invalid: one of its certificates can't be loaded,
    ///     or the signing certificate (the first one) contains neither an ECDSA nor an RSA public key.
    /// </summary>
    public const string X5CInvalid = FidoMetadataDownloadFailures.X5CInvalid;

    /// <summary>
    ///     None of the root certificates of the FIDO Metadata Service embedded in the library can be used: there are none, or one of them can't be loaded.
    /// </summary>
    public const string RootCertificatesInvalid = FidoMetadataDownloadFailures.RootCertificatesInvalid;

    /// <summary>
    ///     The signing certificate chain of the blob is invalid: it can't be built from the signing certificate to one of the root certificates,
    ///     or it doesn't satisfy the chain policy (<see cref="Configuration.Options.X509ChainValidationOptions.OnValidateEmbeddedFidoMetadataBlobJwtChain" />).
    /// </summary>
    public const string ChainInvalid = FidoMetadataDownloadFailures.ChainInvalid;

    /// <summary>
    ///     The signature of the JWT is not valid for the key of the signing certificate (the first certificate in the 'x5c' member), or its algorithm is not acceptable.
    /// </summary>
    public const string SignatureInvalid = FidoMetadataDownloadFailures.SignatureInvalid;

    /// <summary>
    ///     The payload of the JWT is not a valid base64url string, or it can't be deserialized into a MetadataBLOBPayloadJSON.
    /// </summary>
    public const string PayloadInvalid = FidoMetadataDownloadFailures.PayloadInvalid;
}
