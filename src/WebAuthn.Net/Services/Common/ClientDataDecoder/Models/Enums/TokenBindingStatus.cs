using System.Runtime.Serialization;

namespace WebAuthn.Net.Services.Common.ClientDataDecoder.Models.Enums;

/// <summary>
///     Token Binding Status
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-tokenbindingstatus">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.8.1. Client Data Used in WebAuthn Signatures (dictionary CollectedClientData)</a>
/// </remarks>
public enum TokenBindingStatus
{
    /// <summary>
    ///     Indicates the client supports token binding, but it was not negotiated when communicating with the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>.
    /// </summary>
    [EnumMember(Value = "present")]
    Present = 0,

    /// <summary>
    ///     Indicates token binding was used when communicating with the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>. In this case, the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-tokenbinding-id">id</a> member MUST be
    ///     present.
    /// </summary>
    [EnumMember(Value = "supported")]
    Supported = 1
}
