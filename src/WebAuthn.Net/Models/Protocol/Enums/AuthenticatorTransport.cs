using System.Runtime.Serialization;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     Authenticator Transport Enumeration
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enum-transport">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.8.4. Authenticator Transport Enumeration</a>
/// </remarks>
public enum AuthenticatorTransport
{
    /// <summary>
    ///     Indicates the respective <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> can be contacted over removable USB.
    /// </summary>
    [EnumMember(Value = "usb")]
    Usb = 0,

    /// <summary>
    ///     Indicates the respective <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> can be contacted over Near Field Communication (NFC).
    /// </summary>
    [EnumMember(Value = "nfc")]
    Nfc = 1,

    /// <summary>
    ///     Indicates the respective <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> can be contacted over Bluetooth Smart (Bluetooth Low Energy / BLE).
    /// </summary>
    [EnumMember(Value = "ble")]
    Ble = 2,

    /// <summary>
    ///     Indicates the respective <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> can be contacted over ISO/IEC 7816 smart card with contacts.
    /// </summary>
    [EnumMember(Value = "smart-card")]
    SmartCard = 3,

    /// <summary>
    ///     Indicates the respective <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> can be contacted using a combination of (often separate) data-transport and proximity mechanisms. This supports, for example, authentication on a desktop
    ///     computer using a smartphone.
    /// </summary>
    [EnumMember(Value = "hybrid")]
    Hybrid = 4,

    /// <summary>
    ///     Indicates the respective <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> is contacted using a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-device">client device-specific</a> transport, i.e., it is a
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#platform-authenticators">platform authenticator</a>. These authenticators are not removable from the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-device">client device</a>.
    /// </summary>
    [EnumMember(Value = "internal")]
    Internal = 5
}
