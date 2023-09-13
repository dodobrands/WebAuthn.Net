using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Models.Protocol.Creation;

/// <summary>
///     Credential request options.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/credential-management-1/#credentialcreationoptions-dictionary">Credential Management Level 1 - § 2.4. The CredentialCreationOptions Dictionary</a>
///     <br />
///     <a href="https://www.w3.org/TR/webauthn-3/#sctn-credentialcreationoptions-extension">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.1.1. CredentialCreationOptions Dictionary Extension</a>
/// </remarks>
public class CredentialCreationOptions
{
    /// <summary>
    ///     Constructs <see cref="CredentialCreationOptions" />.
    /// </summary>
    /// <param name="publicKey">Options for credential creation.</param>
    /// <exception cref="ArgumentNullException">If the parameter <paramref name="publicKey" /> is equal to <see langword="null" />.</exception>
    public CredentialCreationOptions(PublicKeyCredentialCreationOptions publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey, nameof(publicKey));
        PublicKey = publicKey;
    }

    /// <summary>
    ///     Options for credential creation.
    /// </summary>
    [JsonPropertyName("publicKey")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public PublicKeyCredentialCreationOptions PublicKey { get; }
}
