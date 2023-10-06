using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Models.Protocol.RegistrationCeremony;

/// <summary>
///     Credential request options.
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://w3c.github.io/webappsec-credential-management/#credentialcreationoptions-dictionary">Credential Management Level 1 - §2.4. The CredentialCreationOptions Dictionary</a>
///     </para>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-credentialrequestoptions-extension">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.1.2. CredentialRequestOptions Dictionary Extension</a>
///     </para>
/// </remarks>
public class CredentialCreationOptions
{
    /// <summary>
    ///     Constructs <see cref="CredentialCreationOptions" />.
    /// </summary>
    /// <param name="publicKey">Options for credential creation.</param>
    /// <exception cref="ArgumentNullException"><paramref name="publicKey" /> is <see langword="null" /></exception>
    [JsonConstructor]
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
