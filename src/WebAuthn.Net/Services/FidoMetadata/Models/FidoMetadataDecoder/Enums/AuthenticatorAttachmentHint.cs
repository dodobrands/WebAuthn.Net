using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;

/// <summary>
///     Authenticator Attachment Hint
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#authenticator-attachment-hints">FIDO Registry of Predefined Values - §3.4 Authenticator Attachment Hints</a>
///     </para>
/// </remarks>
[Flags]
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum AuthenticatorAttachmentHint : ushort
{
    /// <summary>
    ///     <para>This flag may be set to indicate that the authenticator is permanently attached to the FIDO User Device.</para>
    ///     <para>A device such as a smartphone may have authenticator functionality that is able to be used both locally and remotely. In such a case, the FIDO client must filter and exclusively report only the relevant bit during Discovery and when performing policy matching.</para>
    ///     <para>This flag cannot be combined with any other ATTACHMENT_HINT flags.</para>
    /// </summary>
    [EnumMember(Value = "internal")]
    ATTACHMENT_HINT_INTERNAL = 0x0001,

    /// <summary>
    ///     <para>This flag may be set to indicate, for a hardware-based authenticator, that it is removable or remote from the FIDO User Device.</para>
    ///     <para>
    ///         A device such as a smartphone may have authenticator functionality that is able to be used both locally and remotely. In such a case, the FIDO UAF Client must filter and exclusively report only the relevant bit during discovery and when performing policy matching. This
    ///         flag must be combined with one or more other ATTACHMENT_HINT flag(s).
    ///     </para>
    /// </summary>
    [EnumMember(Value = "external")]
    ATTACHMENT_HINT_EXTERNAL = 0x0002,

    /// <summary>
    ///     This flag may be set to indicate that an external authenticator currently has an exclusive wired connection, e.g. through USB, Firewire or similar, to the FIDO User Device.
    /// </summary>
    [EnumMember(Value = "wired")]
    ATTACHMENT_HINT_WIRED = 0x0004,

    /// <summary>
    ///     This flag may be set to indicate that an external authenticator communicates with the FIDO User Device through a personal area or otherwise non-routed wireless protocol, such as Bluetooth or NFC.
    /// </summary>
    [EnumMember(Value = "wireless")]
    ATTACHMENT_HINT_WIRELESS = 0x0008,

    /// <summary>
    ///     This flag may be set to indicate that an external authenticator is able to communicate by NFC to the FIDO User Device. As part of authenticator metadata, or when reporting characteristics through discovery, if this flag is set, the ATTACHMENT_HINT_WIRELESS flag should also
    ///     be set as well.
    /// </summary>
    [EnumMember(Value = "nfc")]
    ATTACHMENT_HINT_NFC = 0x0010,

    /// <summary>
    ///     This flag may be set to indicate that an external authenticator is able to communicate using Bluetooth with the FIDO User Device. As part of authenticator metadata, or when reporting characteristics through discovery, if this flag is set, the ATTACHMENT_HINT_WIRELESS flag
    ///     should also be set.
    /// </summary>
    [EnumMember(Value = "bluetooth")]
    ATTACHMENT_HINT_BLUETOOTH = 0x0020,

    /// <summary>
    ///     This flag may be set to indicate that the authenticator is connected to the FIDO User Device over a non-exclusive network (e.g. over a TCP/IP LAN or WAN, as opposed to a PAN or point-to-point connection).
    /// </summary>
    [EnumMember(Value = "network")]
    ATTACHMENT_HINT_NETWORK = 0x0040,

    /// <summary>
    ///     This flag may be set to indicate that an external authenticator is in a "ready" state. This flag is set by the ASM at its discretion.
    /// </summary>
    [EnumMember(Value = "ready")]
    ATTACHMENT_HINT_READY = 0x0080,

    /// <summary>
    ///     This flag may be set to indicate that an external authenticator is able to communicate using WiFi Direct with the FIDO User Device. As part of authenticator metadata and when reporting characteristics through discovery, if this flag is set, the ATTACHMENT_HINT_WIRELESS flag
    ///     should also be set.
    /// </summary>
    [EnumMember(Value = "wifi_direct")]
    ATTACHMENT_HINT_WIFI_DIRECT = 0x0100
}
