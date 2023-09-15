using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Models.Protocol.AuthenticationCeremony;

/// <summary>
///     Credential request options.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/credential-management-1/#credentialrequestoptions-dictionary">Credential Management Level 1 - § 2.3.1. The CredentialRequestOptions Dictionary</a>
///     <br />
///     <a href="https://www.w3.org/TR/webauthn-3/#sctn-credentialrequestoptions-extension">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.1.2. CredentialRequestOptions Dictionary Extension</a>
/// </remarks>
public class CredentialRequestOptions
{
    /// <summary>
    ///     Constructs <see cref="CredentialRequestOptions" />.
    /// </summary>
    /// <param name="mediation">Mediation requirements for a given credential request</param>
    /// <param name="publicKey">Options for assertion generation.</param>
    /// <exception cref="ArgumentNullException">If the <paramref name="publicKey" /> parameter is <see langword="null" />.</exception>
    /// <exception cref="InvalidEnumArgumentException">If the <paramref name="mediation" /> parameter contains a value not defined in the <see cref="CredentialMediationRequirement" /> enum.</exception>
    [JsonConstructor]
    public CredentialRequestOptions(
        CredentialMediationRequirement? mediation,
        PublicKeyCredentialRequestOptions publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey, nameof(publicKey));
        if (mediation.HasValue)
        {
            if (!Enum.IsDefined(mediation.Value))
            {
                throw new InvalidEnumArgumentException(nameof(mediation), (int) mediation.Value, typeof(CredentialMediationRequirement));
            }

            Mediation = mediation.Value;
        }

        PublicKey = publicKey;
    }

    /// <summary>
    ///     Specifies the mediation requirements for a given credential request. Defaulting to <see cref="CredentialMediationRequirement.Optional" />.
    /// </summary>
    [JsonPropertyName("mediation")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public CredentialMediationRequirement? Mediation { get; }

    /// <summary>
    ///     Options for assertion generation.
    /// </summary>
    [JsonPropertyName("publicKey")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public PublicKeyCredentialRequestOptions PublicKey { get; }
}
