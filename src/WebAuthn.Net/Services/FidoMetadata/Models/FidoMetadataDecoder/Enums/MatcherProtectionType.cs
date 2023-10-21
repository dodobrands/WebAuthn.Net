using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;

/// <summary>
///     Matcher Protection Type
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#matcher-protection-types">FIDO Registry of Predefined Values - §3.3 Matcher Protection Types</a>
///     </para>
/// </remarks>
[Flags]
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum MatcherProtectionType : ushort
{
    /// <summary>
    ///     This flag must be set if the authenticator's matcher is running in software. Exclusive in authenticator metadata with <see cref="MATCHER_PROTECTION_TEE" />, <see cref="MATCHER_PROTECTION_ON_CHIP" />
    /// </summary>
    [EnumMember(Value = "software")]
    MATCHER_PROTECTION_SOFTWARE = 0x0001,

    /// <summary>
    ///     This flag should be set if the authenticator's matcher is running inside the Trusted Execution Environment [TEE]. Mutually exclusive in authenticator metadata with <see cref="MATCHER_PROTECTION_SOFTWARE" />, <see cref="MATCHER_PROTECTION_ON_CHIP" />
    /// </summary>
    [EnumMember(Value = "tee")]
    MATCHER_PROTECTION_TEE = 0x0002,

    /// <summary>
    ///     This flag should be set if the authenticator's matcher is running on the chip. Mutually exclusive in authenticator metadata with <see cref="MATCHER_PROTECTION_TEE" />, <see cref="MATCHER_PROTECTION_SOFTWARE" />
    /// </summary>
    [EnumMember(Value = "on_chip")]
    MATCHER_PROTECTION_ON_CHIP = 0x0004
}
