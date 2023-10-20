using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateOptions;

/// <summary>
///     Parameters for Credential Generation (dictionary PublicKeyCredentialParameters)
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-credential-params">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.3. Parameters for Credential Generation (dictionary PublicKeyCredentialParameters)</a>
///     </para>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-parseCreationOptionsFromJSON">
///             Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.1.9. Deserialize Registration ceremony options - PublicKeyCredential's
///             parseCreationOptionsFromJSON() Method
///         </a>
///     </para>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictdef-publickeycredentialcreationoptions">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.4. Options for Credential Creation (dictionary PublicKeyCredentialCreationOptions)</a>
///     </para>
/// </remarks>
// ReSharper disable once InconsistentNaming
public class PublicKeyCredentialParametersJSON
{
    /// <summary>
    ///     Constructs <see cref="PublicKeyCredentialParametersJSON" />.
    /// </summary>
    /// <param name="type">
    ///     This member specifies the type of credential to be created. The value SHOULD be a member of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialtype">PublicKeyCredentialType</a> but
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore unknown values, ignoring any <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictdef-publickeycredentialparameters">PublicKeyCredentialParameters</a>
    ///     with an unknown <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialparameters-type">type</a>.
    /// </param>
    /// <param name="alg">This member specifies the cryptographic signature algorithm with which the newly generated credential will be used, and thus also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.</param>
    public PublicKeyCredentialParametersJSON(string type, long alg)
    {
        Type = type;
        Alg = alg;
    }

    /// <summary>
    ///     This member specifies the type of credential to be created. The value SHOULD be a member of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialtype">PublicKeyCredentialType</a> but
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore unknown values, ignoring any <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictdef-publickeycredentialparameters">PublicKeyCredentialParameters</a>
    ///     with an unknown <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialparameters-type">type</a>.
    /// </summary>
    /// <remarks>DOMString</remarks>
    [Required]
    [JsonPropertyName("type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Type { get; }

    /// <summary>
    ///     This member specifies the cryptographic signature algorithm with which the newly generated credential will be used, and thus also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
    /// </summary>
    /// <remarks>
    ///     <para>COSEAlgorithmIdentifier</para>
    ///     <para>We use "alg" as the latter member name, rather than spelling-out "algorithm", because it will be serialized into a message to the authenticator, which may be sent over a low-bandwidth link.</para>
    /// </remarks>
    [Required]
    [JsonPropertyName("alg")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public long Alg { get; }
}
