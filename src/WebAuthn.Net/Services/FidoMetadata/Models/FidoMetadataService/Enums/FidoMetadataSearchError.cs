namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService.Enums;

/// <summary>
///     The reason why <see cref="IFidoMetadataSearchService{TContext}" /> has returned no metadata for the authenticator.
/// </summary>
public enum FidoMetadataSearchError
{
    /// <summary>
    ///     <para>
    ///         There is no usable entry for the authenticator in the metadata: there is no entry for it at all (for example, because the authenticator is not certified),
    ///         or the entry has no metadata statement, or the metadata statement has no root certificate that is valid at the current time.
    ///     </para>
    ///     <para>
    ///         The metadata doesn't say that the authenticator can't be trusted, so its attestation may still be verified against other trust anchors (for example, the root certificates embedded in the library).
    ///     </para>
    /// </summary>
    NotFound = 1,

    /// <summary>
    ///     <para>No metadata obtained from the FIDO Metadata Service is available (for example, before the first successful ingestion), so the entry for the authenticator can't be found.</para>
    ///     <para>
    ///         Just like with <see cref="NotFound" />, the metadata doesn't say that the authenticator can't be trusted, so its attestation may still be verified against other trust anchors
    ///         (for example, the root certificates embedded in the library).
    ///     </para>
    /// </summary>
    MetadataNotAvailable = 2,

    /// <summary>
    ///     <para>
    ///         There is an entry for the authenticator in the metadata, but its status reports don't allow to trust the authenticator
    ///         (for example, the status of the authenticator is REVOKED or ATTESTATION_KEY_COMPROMISE).
    ///     </para>
    ///     <para>
    ///         The attestation of the authenticator must be rejected, even if it can be verified against other trust anchors (for example, the root certificates embedded in the library):
    ///         the statuses of the FIDO Metadata Service are the only way the library learns that an authenticator model is revoked.
    ///     </para>
    /// </summary>
    Untrusted = 3
}
