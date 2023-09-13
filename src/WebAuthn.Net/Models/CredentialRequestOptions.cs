using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using WebAuthn.Net.Models.Enums;

namespace WebAuthn.Net.Models;

/// <summary>
///     Credential request options. <see cref="https://www.w3.org/TR/webauthn-2/#sctn-credentialrequestoptions-extension"/>
/// </summary>
public class CredentialRequestOptions
{
    /// <summary>
    ///     Constructs <see cref="CredentialRequestOptions" />.
    /// </summary>
    /// <param name="mediation">Mediation requirements for a given credential request</param>
    /// <param name="publicKey">Options for credential creation.</param>
    /// <exception cref="ArgumentException">If the value of the parameter <paramref name="mediation"/> contains a value that is not defined in the <see cref="CredentialMediationRequirement"/> enum.</exception>
    /// <exception cref="ArgumentNullException">If the parameter <paramref name="publicKey"/> is equal to <see langword="null"/>.</exception>
    [JsonConstructor]
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
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CredentialMediationRequirement? Mediation { get; }

    /// <summary>
    ///     Options for credential creation.
    ///     <br />
    ///     <a href="https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrequestoptions">Web Authentication: An API for accessing Public Key Credentials Level 2. § 5.5. Options for Assertion Generation</a> (dictionary <see cref="PublicKeyCredentialRequestOptions" />)
    /// </summary>
    [JsonPropertyName("publicKey")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public PublicKeyCredentialRequestOptions PublicKey { get; }
}
