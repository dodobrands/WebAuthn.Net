using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;

/// <summary>
///     The FIDO protocol family.
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html#dom-metadatastatement-protocolfamily">FIDO Metadata Statement - Metadata Keys</a>
///     </para>
/// </remarks>
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum ProtocolFamily : byte
{
    /// <summary>
    ///     UAF authenticator
    /// </summary>
    [EnumMember(Value = "uaf")]
    uaf = 1,

    /// <summary>
    ///     U2F authenticator
    /// </summary>
    [EnumMember(Value = "u2f")]
    u2f = 2,

    /// <summary>
    ///     FIDO2/WebAuthentication authenticator
    /// </summary>
    [EnumMember(Value = "fido2")]
    fido2 = 3
}
