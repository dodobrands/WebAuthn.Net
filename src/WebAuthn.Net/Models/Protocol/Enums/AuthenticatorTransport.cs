using System.Runtime.Serialization;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     Authenticator Transport Enumeration
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/webauthn-3/#enum-transport">Web Authentication: An API for accessing Public Key Credentials Level 3 - Authenticator Transport Enumeration (enum AuthenticatorTransport)</a>
///     </para>
///     <para>
///         <a href="https://www.w3.org/TR/webauthn-3/#authenticator">Authenticators</a> may implement various <a href="https://www.w3.org/TR/webauthn-3/#enum-transport">transports</a> for communicating with <a href="https://www.w3.org/TR/webauthn-3/#client">clients</a>. This
///         enumeration defines hints as to how clients might communicate with a particular authenticator in order to obtain an assertion for a specific credential. Note that these hints represent the
///         <a href="https://www.w3.org/TR/webauthn-3/#webauthn-relying-party">WebAuthn Relying Party’s</a> best belief as to how an authenticator may be reached. A <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> will typically learn of the supported
///         transports for a <a href="https://www.w3.org/TR/webauthn-3/#public-key-credential">public key credential</a> via <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-gettransports">getTransports()</a>.
///     </para>
/// </remarks>
public enum AuthenticatorTransport
{
    /// <summary>
    ///     Indicates the respective <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> can be contacted over removable USB.
    /// </summary>
    [EnumMember(Value = "usb")]
    Usb = 0,

    /// <summary>
    ///     Indicates the respective <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> can be contacted over Near Field Communication (NFC).
    /// </summary>
    [EnumMember(Value = "nfc")]
    Nfc = 1,

    /// <summary>
    ///     Indicates the respective <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> can be contacted over Bluetooth Smart (Bluetooth Low Energy / BLE).
    /// </summary>
    [EnumMember(Value = "ble")]
    Ble = 2,

    /// <summary>
    ///     Indicates the respective <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> can be contacted over ISO/IEC 7816 smart card with contacts.
    /// </summary>
    [EnumMember(Value = "smart-card")]
    SmartCard = 3,

    /// <summary>
    ///     Indicates the respective <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> can be contacted using a combination of (often separate) data-transport and proximity mechanisms. This supports, for example, authentication on a desktop computer using a
    ///     smartphone.
    /// </summary>
    [EnumMember(Value = "hybrid")]
    Hybrid = 4,

    /// <summary>
    ///     Indicates the respective <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> is contacted using a <a href="https://www.w3.org/TR/webauthn-3/#client-device">client device-specific</a> transport, i.e., it is a
    ///     <a href="https://www.w3.org/TR/webauthn-3/#platform-authenticators">platform authenticator</a>. These authenticators are not removable from the <a href="https://www.w3.org/TR/webauthn-3/#client-device">client device</a>.
    /// </summary>
    [EnumMember(Value = "internal")]
    Internal = 5
}
