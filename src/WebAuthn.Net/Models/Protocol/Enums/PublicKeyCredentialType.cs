using System.Runtime.Serialization;

namespace WebAuthn.Net.Models.Protocol.Enums;

/// <summary>
///     Credential Type Enumeration
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/webauthn-3/#enum-credentialType">Web Authentication: An API for accessing Public Key Credentials Level 3 - Credential Type Enumeration (enum PublicKeyCredentialType)</a>
///     </para>
///     <para>
///         This enumeration defines the valid credential types. It is an extension point; values can be added to it in the future, as more credential types are defined. The values of this enumeration are used for versioning the Authentication Assertion and attestation structures
///         according to the type of the authenticator.
///     </para>
/// </remarks>
public enum PublicKeyCredentialType
{
    /// <summary>
    ///     Public key.
    /// </summary>
    [EnumMember(Value = "public-key")]
    PublicKey = 0
}
