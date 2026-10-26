using System;
using System.Reflection;
using WebAuthn.Net.Configuration.Options;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataBackgroundIngest;

/// <summary>
///     Options for background ingestion of metadata from the FIDO Metadata Service.
/// </summary>
/// <remarks>
///     <para>
///         At start-up, the blob embedded in the application (<see cref="EmbeddedBlobAssembly" /> and <see cref="EmbeddedBlobResourceName" />) is loaded first, if it is configured.
///         Then the blob is loaded from the FIDO Metadata Service: once it is loaded, the next refresh takes place after <see cref="IngestInterval" />,
///         and after an unsuccessful attempt the next attempt takes place after <see cref="RetryInterval" />.
///     </para>
///     <para>
///         If the blob embedded in the application is loaded, the start of the application doesn't wait for the FIDO Metadata Service: the blob is downloaded in the background right away.
///         Otherwise, the start of the application waits for the first attempt to load the blob from the FIDO Metadata Service.
///     </para>
/// </remarks>
public class FidoMetadataBackgroundIngestHostedServiceOptions
{
    /// <summary>
    ///     The interval between the refreshes of the metadata after the blob has been loaded from the FIDO Metadata Service. Default is 1 day (24 hours),
    ///     as <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-considerations">the FIDO Metadata Service recommends</a> for typical applications.
    /// </summary>
    /// <remarks>
    ///     A value that is not positive is not used: the default value is used instead, and an error is logged.
    /// </remarks>
    public TimeSpan IngestInterval { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    ///     The interval between the attempts to load the blob from the FIDO Metadata Service after an unsuccessful attempt (the blob can't be downloaded, verified or decoded, or an exception occurred).
    ///     The attempts are repeated with this interval until the blob is loaded, after which the metadata is refreshed every <see cref="IngestInterval" />. Default is 1 minute.
    /// </summary>
    /// <remarks>
    ///     A value that is not positive is not used: the default value is used instead, and an error is logged.
    /// </remarks>
    public TimeSpan RetryInterval { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    ///     Flag responsible for whether the start of the application fails (an <see cref="InvalidOperationException" /> is thrown from <see cref="FidoMetadataBackgroundIngestHostedService.StartAsync" />)
    ///     when no metadata could be loaded at start-up: neither the blob embedded in the application nor the blob from the FIDO Metadata Service. Defaults to <see langword="false" />.
    /// </summary>
    /// <remarks>
    ///     The flag applies only to the start-up. The failures of the background refresh never throw: they are logged and counted, and the attempts are repeated every <see cref="RetryInterval" />.
    /// </remarks>
    public bool ThrowExceptionOnFailure { get; set; }

    /// <summary>
    ///     The assembly that contains the FIDO Metadata Service blob embedded in the application as a manifest resource (see <see cref="EmbeddedBlobResourceName" />).
    ///     Defaults to <see langword="null" />: no blob is embedded in the application.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         The embedded blob is loaded at start-up before the blob from the FIDO Metadata Service, so that the application starts with metadata and works even if the FIDO Metadata Service is unavailable.
    ///         The blob downloaded from the FIDO Metadata Service replaces it as soon as it is loaded. If the embedded blob can't be loaded, the reason is logged and counted, and the metadata is loaded from the FIDO Metadata Service only.
    ///     </para>
    ///     <para>
    ///         The embedded blob has to be the blob exactly as the FIDO Metadata Service serves it (a JWS in the compact serialization). It is verified like a downloaded blob, except that the validity period
    ///         and the revocation status of its signing certificates are not checked (see <see cref="X509ChainValidationOptions.OnValidateEmbeddedFidoMetadataBlobJwtChain" />).
    ///         An embedded blob that is not newer than the metadata in use (for example, a persistent storage keeps a blob downloaded before the restart of the application) is not ingested.
    ///     </para>
    ///     <para>
    ///         Both <see cref="EmbeddedBlobAssembly" /> and <see cref="EmbeddedBlobResourceName" /> have to be set. If only one of them is set, the embedded blob is not loaded and a warning is logged.
    ///     </para>
    /// </remarks>
    public Assembly? EmbeddedBlobAssembly { get; set; }

    /// <summary>
    ///     The name of the manifest resource of <see cref="EmbeddedBlobAssembly" /> that contains the FIDO Metadata Service blob embedded in the application, as <see cref="Assembly.GetManifestResourceNames" /> reports it
    ///     (by default, the root namespace of the project, followed by the path of the file with dots instead of the directory separators, for example <c>MyApp.FidoMetadata.blob.jwt</c>).
    ///     Defaults to <see langword="null" />: no blob is embedded in the application.
    /// </summary>
    public string? EmbeddedBlobResourceName { get; set; }
}
