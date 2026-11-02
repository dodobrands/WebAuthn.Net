using System;
using System.Reflection;

namespace WebAuthn.Net.Configuration.Options.AttestationStatements;

/// <summary>
///     Options that define the certificate revocation status list of the Android attestation keys embedded in the application: the assembly and the name of its manifest resource that contains the status list.
/// </summary>
/// <remarks>
///     <para>
///         Both values are required, so the status list embedded in the application is either specified completely or not specified at all
///         (<see cref="AndroidKeyAttestationStatusListOptions.EmbeddedStatusList" /> is <see langword="null" />).
///     </para>
///     <para>
///         The constructor checks only the values themselves. Whether the assembly contains the resource and whether the resource contains a valid status list is checked when the status list is loaded:
///         a status list that can't be loaded is logged and counted, and the status list is then downloaded only.
///     </para>
/// </remarks>
public class AndroidKeyAttestationEmbeddedStatusListOptions
{
    /// <summary>
    ///     Constructs <see cref="AndroidKeyAttestationEmbeddedStatusListOptions" />.
    /// </summary>
    /// <param name="assembly">The assembly that contains the status list as a manifest resource.</param>
    /// <param name="resourceName">
    ///     The name of the manifest resource that contains the status list, as <see cref="Assembly.GetManifestResourceNames" /> reports it (by default, the root namespace of the project,
    ///     followed by the path of the file with dots instead of the directory separators, for example <c>MyApp.AndroidKey.status.json</c>).
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="assembly" /> or <paramref name="resourceName" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException"><paramref name="resourceName" /> is empty or consists only of white-space characters</exception>
    public AndroidKeyAttestationEmbeddedStatusListOptions(Assembly assembly, string resourceName)
    {
        ArgumentNullException.ThrowIfNull(assembly);
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceName);
        Assembly = assembly;
        ResourceName = resourceName;
    }

    /// <summary>
    ///     The assembly that contains the status list as a manifest resource.
    /// </summary>
    public Assembly Assembly { get; }

    /// <summary>
    ///     The name of the manifest resource that contains the status list exactly as Google serves it (JSON).
    /// </summary>
    public string ResourceName { get; }
}
