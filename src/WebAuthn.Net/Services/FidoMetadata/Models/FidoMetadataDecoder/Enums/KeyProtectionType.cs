using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;

/// <summary>
///     Key Protection Type
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#user-verification-methods">FIDO Registry of Predefined Values - §3.2 Key Protection Types</a>
///     </para>
/// </remarks>
[Flags]
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum KeyProtectionType : ushort
{
    /// <summary>
    ///     This flag must be set if the authenticator uses software-based key management. Exclusive in authenticator metadata with <see cref="KEY_PROTECTION_HARDWARE" />, <see cref="KEY_PROTECTION_TEE" />, <see cref="KEY_PROTECTION_SECURE_ELEMENT" />.
    /// </summary>
    [EnumMember(Value = "software")]
    KEY_PROTECTION_SOFTWARE = 0x0001,

    /// <summary>
    ///     This flag should be set if the authenticator uses hardware-based key management. Exclusive in authenticator metadata with <see cref="KEY_PROTECTION_SOFTWARE" />.
    /// </summary>
    [EnumMember(Value = "hardware")]
    KEY_PROTECTION_HARDWARE = 0x0002,

    /// <summary>
    ///     This flag should be set if the authenticator uses the Trusted Execution Environment [TEE] for key management. In authenticator metadata, this flag should be set in conjunction with <see cref="KEY_PROTECTION_HARDWARE" />. Mutually exclusive in authenticator metadata with
    ///     <see cref="KEY_PROTECTION_SOFTWARE" />, <see cref="KEY_PROTECTION_SECURE_ELEMENT" />.
    /// </summary>
    [EnumMember(Value = "tee")]
    KEY_PROTECTION_TEE = 0x0004,

    /// <summary>
    ///     This flag should be set if the authenticator uses a Secure Element [SecureElement] for key management. In authenticator metadata, this flag should be set in conjunction with <see cref="KEY_PROTECTION_HARDWARE" />. Mutually exclusive in authenticator metadata with
    ///     <see cref="KEY_PROTECTION_TEE" />, <see cref="KEY_PROTECTION_SOFTWARE" />
    /// </summary>
    [EnumMember(Value = "secure_element")]
    KEY_PROTECTION_SECURE_ELEMENT = 0x0008,

    /// <summary>
    ///     This flag must be set if the authenticator does not store (wrapped) UAuth keys at the client, but relies on a server-provided key handle. This flag must be set in conjunction with one of the other KEY_PROTECTION flags to indicate how the local key handle wrapping key and
    ///     operations are protected. Servers may unset this flag in authenticator policy if they are not prepared to store and return key handles, for example, if they have a requirement to respond indistinguishably to authentication attempts against userIDs that do and do not exist.
    ///     Refer to [UAFProtocol] for more details.
    /// </summary>
    [EnumMember(Value = "remote_handle")]
    KEY_PROTECTION_REMOTE_HANDLE = 0x0010
}
