using System;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataBackgroundIngest;

/// <summary>
///     Options for background ingestion of metadata from the FIDO Metadata Service.
/// </summary>
public class FidoMetadataBackgroundIngestHostedServiceOptions
{
    /// <summary>
    ///     The interval between data refreshes. Default is 1 day (24 hours).
    /// </summary>
    public TimeSpan IngestInterval { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    ///     Flag responsible for whether to throw an exception on a data update failure. Defaults to <see langword="false" />.
    /// </summary>
    public bool ThrowExceptionOnFailure { get; set; }
}
