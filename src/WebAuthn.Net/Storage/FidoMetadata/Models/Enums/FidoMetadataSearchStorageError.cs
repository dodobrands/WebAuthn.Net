namespace WebAuthn.Net.Storage.FidoMetadata.Models.Enums;

/// <summary>
///     The reason why <see cref="IFidoMetadataSearchStorage{TContext}" /> has found no entry in the metadata obtained from the FIDO Metadata Service.
/// </summary>
public enum FidoMetadataSearchStorageError
{
    /// <summary>
    ///     The storage contains metadata, but there is no entry for the authenticator in it (for example, because the authenticator is not certified).
    /// </summary>
    NotFound = 1,

    /// <summary>
    ///     The storage contains no metadata to search in: no blob obtained from the FIDO Metadata Service has been ingested yet (for example, before the first successful ingestion).
    /// </summary>
    MetadataNotAvailable = 2
}
