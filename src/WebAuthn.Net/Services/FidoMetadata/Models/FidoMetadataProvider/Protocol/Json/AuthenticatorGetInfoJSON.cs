using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

/// <summary>
///     authenticatorGetInfo
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetInfo">Client to Authenticator Protocol (CTAP) - §5.4. authenticatorGetInfo (0x04)</a>
///     </para>
/// </remarks>
// ReSharper disable once InconsistentNaming
public class AuthenticatorGetInfoJSON
{
    /// <summary>
    ///     Constructs <see cref="AuthenticatorGetInfoJSON" />.
    /// </summary>
    /// <param name="versions">List of supported versions. Supported versions are: "FIDO_2_0" for CTAP2 / FIDO2 / Web Authentication authenticators and "U2F_V2" for CTAP1/U2F authenticators.</param>
    /// <param name="extensions">List of supported extensions.</param>
    /// <param name="aaguid">The claimed AAGUID. 16 bytes in length and encoded the same as MakeCredential AuthenticatorData, as specified in [WebAuthn].</param>
    /// <param name="options">List of supported options.</param>
    /// <param name="maxMsgSize">Maximum message size supported by the authenticator.</param>
    /// <param name="pinProtocols">List of supported PIN Protocol versions.</param>
    [JsonConstructor]
    public AuthenticatorGetInfoJSON(
        string[] versions,
        string[]? extensions,
        string aaguid,
        Dictionary<string, bool>? options,
        uint? maxMsgSize,
        uint[]? pinProtocols)
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
    [JsonPropertyName("versions")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string[] Versions { get; }

    /// <summary>
    ///     List of supported extensions.
    /// </summary>
    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string[]? Extensions { get; }

    /// <summary>
    ///     The claimed AAGUID. 16 bytes in length and encoded the same as MakeCredential AuthenticatorData, as specified in [WebAuthn].
    /// </summary>
    [JsonPropertyName("aaguid")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Aaguid { get; }

    /// <summary>
    ///     List of supported options.
    /// </summary>
    [JsonPropertyName("options")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public Dictionary<string, bool>? Options { get; }

    /// <summary>
    ///     Maximum message size supported by the authenticator.
    /// </summary>
    [JsonPropertyName("maxMsgSize")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public uint? MaxMsgSize { get; }

    /// <summary>
    ///     List of supported PIN Protocol versions.
    /// </summary>
    [JsonPropertyName("pinProtocols")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public uint[]? PinProtocols { get; }
}
