using System;
using System.Collections.Generic;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

/// <summary>
///     authenticatorGetInfo
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo">Client to Authenticator Protocol (CTAP) - §5.4. authenticatorGetInfo (0x04)</a>
///     </para>
/// </remarks>
public class AuthenticatorGetInfo
{
    /// <summary>
    ///     Constructs <see cref="AuthenticatorGetInfo" />.
    /// </summary>
    /// <param name="versions">List of supported versions. Supported versions are: "FIDO_2_0" for CTAP2 / FIDO2 / Web Authentication authenticators and "U2F_V2" for CTAP1/U2F authenticators.</param>
    /// <param name="extensions">List of supported extensions.</param>
    /// <param name="aaguid">The claimed AAGUID. 16 bytes in length and encoded the same as MakeCredential AuthenticatorData, as specified in [WebAuthn].</param>
    /// <param name="options">List of supported options.</param>
    /// <param name="maxMsgSize">Maximum message size supported by the authenticator.</param>
    /// <param name="pinProtocols">List of supported PIN Protocol versions.</param>
    public AuthenticatorGetInfo(
        string[] versions,
        string[]? extensions,
        Guid aaguid,
        Dictionary<string, bool>? options,
        ulong? maxMsgSize,
        ulong[]? pinProtocols)
    {
        Versions = versions;
        Extensions = extensions;
        Aaguid = aaguid;
        Options = options;
        MaxMsgSize = maxMsgSize;
        PinProtocols = pinProtocols;
    }

    /// <summary>
    ///     List of supported versions. Supported versions are: "FIDO_2_0" for CTAP2 / FIDO2 / Web Authentication authenticators and "U2F_V2" for CTAP1/U2F authenticators.
    /// </summary>
    public string[] Versions { get; }

    /// <summary>
    ///     List of supported extensions.
    /// </summary>
    public string[]? Extensions { get; }

    /// <summary>
    ///     The claimed AAGUID. 16 bytes in length and encoded the same as MakeCredential AuthenticatorData, as specified in [WebAuthn].
    /// </summary>
    public Guid Aaguid { get; }

    /// <summary>
    ///     List of supported options.
    /// </summary>
    public Dictionary<string, bool>? Options { get; }

    /// <summary>
    ///     Maximum message size supported by the authenticator.
    /// </summary>
    public ulong? MaxMsgSize { get; }

    /// <summary>
    ///     List of supported PIN Protocol versions.
    /// </summary>
    public ulong[]? PinProtocols { get; }
}
