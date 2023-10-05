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
///     <para>
///         <a href="https://w3c.github.io/webappsec-credential-management/#credentialrequestoptions-dictionary">Credential Management Level 1 - §2.3.1. The CredentialRequestOptions Dictionary</a>
///     </para>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-credentialrequestoptions-extension">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.1.2. CredentialRequestOptions Dictionary Extension</a>
///     </para>
/// </remarks>
public class CredentialRequestOptions
{
    /// <summary>
    ///     Constructs <see cref="CredentialRequestOptions" />.
    /// </summary>
    /// <param name="mediation">
    ///     This property specifies the mediation requirements for a given credential request. The meaning of each enum value is described below in
    ///     <a href="https://w3c.github.io/webappsec-credential-management/#enumdef-credentialmediationrequirement">CredentialMediationRequirement</a>. Processing details are defined in
    ///     <a href="https://w3c.github.io/webappsec-credential-management/#algorithm-request">§2.5.1 Request a Credential</a>.
    /// </param>
    /// <param name="publicKey">Options for assertion generation.</param>
    /// <exception cref="ArgumentNullException"><paramref name="publicKey" /> is <see langword="null" /></exception>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="mediation" /> contains a value that is not defined in <see cref="CredentialMediationRequirement" /></exception>
    [JsonConstructor]
    public CredentialRequestOptions(
        CredentialMediationRequirement? mediation,
        PublicKeyCredentialRequestOptions publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
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
    ///     This property specifies the mediation requirements for a given credential request. The meaning of each enum value is described below in <a href="https://w3c.github.io/webappsec-credential-management/#enumdef-credentialmediationrequirement">CredentialMediationRequirement</a>.
    ///     Processing details are defined in <a href="https://w3c.github.io/webappsec-credential-management/#algorithm-request">§2.5.1 Request a Credential</a>.
    /// </summary>
    [JsonPropertyName("attestationObject")]
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
