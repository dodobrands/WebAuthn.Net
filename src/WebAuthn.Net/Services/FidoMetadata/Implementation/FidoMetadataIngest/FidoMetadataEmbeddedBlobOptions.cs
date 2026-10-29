using System;
using System.Reflection;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataIngest;

/// <summary>
///     Options that define the FIDO Metadata Service blob embedded in the application: the assembly and the name of its manifest resource that contains the blob.
/// </summary>
/// <remarks>
///     <para>
///         Both values are required, so the blob embedded in the application is either specified completely or not specified at all
///         (<see cref="FidoMetadataIngestBackgroundServiceOptions.EmbeddedBlob" /> is <see langword="null" />).
///     </para>
///     <para>
///         The constructor checks only the values themselves. Whether the assembly contains the resource and whether the resource contains a valid blob is checked when the blob is loaded:
///         a blob that can't be loaded is logged and counted, and the metadata is then loaded from the FIDO Metadata Service only.
///     </para>
/// </remarks>
public class FidoMetadataEmbeddedBlobOptions
{
    /// <summary>
    ///     Constructs <see cref="FidoMetadataEmbeddedBlobOptions" />.
    /// </summary>
    /// <param name="assembly">The assembly that contains the blob as a manifest resource.</param>
    /// <param name="resourceName">
    ///     The name of the manifest resource that contains the blob, as <see cref="Assembly.GetManifestResourceNames" /> reports it (by default, the root namespace of the project,
    ///     followed by the path of the file with dots instead of the directory separators, for example <c>MyApp.FidoMetadata.blob.jwt</c>).
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="assembly" /> or <paramref name="resourceName" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException"><paramref name="resourceName" /> is empty or consists only of white-space characters</exception>
    public FidoMetadataEmbeddedBlobOptions(Assembly assembly, string resourceName)
    {
        ArgumentNullException.ThrowIfNull(assembly);
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceName);
        Assembly = assembly;
        ResourceName = resourceName;
    }

    /// <summary>
    ///     The assembly that contains the blob as a manifest resource.
    /// </summary>
    public Assembly Assembly { get; }

    /// <summary>
    ///     The name of the manifest resource that contains the blob exactly as the FIDO Metadata Service serves it (a JWS in the compact serialization).
    /// </summary>
    public string ResourceName { get; }
}
