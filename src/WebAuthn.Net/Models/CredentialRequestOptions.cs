using System;
using System.Text.Json.Serialization;
using WebAuthn.Net.Models.Enums;

namespace WebAuthn.Net.Models;

/// <summary>
///     Credential request options.
/// </summary>
public class CredentialRequestOptions
{
    /// <summary>
    ///     Constructs <see cref="CredentialRequestOptions" />.
    /// </summary>
    /// <param name="mediation">Mediation requirements for a given credential request</param>
    /// <param name="publicKey">Options for credential creation.</param>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="ArgumentNullException"></exception>
    public CredentialRequestOptions(
        CredentialMediationRequirement? mediation,
        PublicKeyCredentialRequestOptions publicKey)
    {
        if (mediation.HasValue)
        {
            if (!Enum.IsDefined(mediation.Value))
            {
                throw new ArgumentException("Incorrect value", nameof(mediation));
            }

            Mediation = mediation.Value;
        }

        ArgumentNullException.ThrowIfNull(publicKey, nameof(publicKey));
        PublicKey = publicKey;
    }

    /// <summary>
    ///     Specifies the mediation requirements for a given credential request. Defaulting to <see cref="CredentialMediationRequirement.Optional" />.
    /// </summary>
    [JsonPropertyName("mediation")]
    public CredentialMediationRequirement? Mediation { get; } = CredentialMediationRequirement.Optional;

    /// <summary>
    ///     Options for credential creation.
    ///     <br />
    ///     <a href="https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrequestoptions">Web Authentication: An API for accessing Public Key Credentials Level 2. § 5.5. Options for Assertion Generation</a> (dictionary <see cref="PublicKeyCredentialRequestOptions" />)
    /// </summary>
    [JsonPropertyName("publicKey")]
    public PublicKeyCredentialRequestOptions PublicKey { get; }
}
