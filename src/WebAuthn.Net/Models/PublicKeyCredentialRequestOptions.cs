using System.Text.Json.Serialization;

namespace WebAuthn.Net.Models;

/// <summary>
///     Options for credential creation.
///     <br />
///     <a href="https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrequestoptions">Web Authentication: An API for accessing Public Key Credentials Level 2. § 5.5. Options for Assertion Generation</a> (dictionary <see cref="PublicKeyCredentialRequestOptions" />)
/// </summary>
public class PublicKeyCredentialRequestOptions
{
    public PublicKeyCredentialRequestOptions(byte[] challenge)
    {
        Challenge = challenge;
    }

    /// <summary>
    ///     Represents a challenge that the selected <a href="https://www.w3.org/TR/webauthn-2/#authenticator">authenticator</a> signs, along with other data, when producing an authentication assertion.
    /// </summary>
    [JsonPropertyName("challenge")]
    public byte[] Challenge { get; }
}
