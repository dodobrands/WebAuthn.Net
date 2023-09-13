using System.Text.Json.Serialization;

namespace WebAuthn.Net.Models;

/// <summary>
///     CredentialCreationOptions. <see cref="https://www.w3.org/TR/webauthn-2/#sctn-credentialcreationoptions-extension" />
/// </summary>
public class CredentialCreationOptions
{
    public CredentialCreationOptions(PublicKeyCredentialCreationOptions publicKey)
    {
        PublicKey = publicKey;
    }

    [JsonPropertyName("publicKey")]
    public PublicKeyCredentialCreationOptions PublicKey { get; }
}
