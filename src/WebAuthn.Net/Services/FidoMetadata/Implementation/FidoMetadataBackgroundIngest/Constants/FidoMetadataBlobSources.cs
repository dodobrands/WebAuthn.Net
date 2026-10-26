namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataBackgroundIngest.Constants;

/// <summary>
///     The sources from which <see cref="FidoMetadataBackgroundIngestHostedService" /> loads the FIDO Metadata Service blob. They are the values of the <c>source</c> tag of the
///     <c>webauthn.mds.ingest.exceptions</c> counter (<see cref="Metrics.IFidoMetadataCounters.IncrementIngestException" />).
/// </summary>
public static class FidoMetadataBlobSources
{
    /// <summary>
    ///     The blob embedded in the application (<see cref="FidoMetadataBackgroundIngestHostedServiceOptions.EmbeddedBlobAssembly" />), loaded at start-up.
    /// </summary>
    public const string Embedded = "embedded";

    /// <summary>
    ///     The blob downloaded from the FIDO Metadata Service, at start-up and in the background.
    /// </summary>
    public const string FidoMetadataService = "mds";
}
