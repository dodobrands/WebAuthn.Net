using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Models.Protocol.RegistrationCeremony;

/// <summary>
///     Parameters for Credential Generation
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#dictionary-credential-params">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.3. Parameters for Credential Generation</a>
/// </remarks>
public class PublicKeyCredentialParameters
{
    /// <summary>
    ///     Constructs <see cref="PublicKeyCredentialParameters" />.
    /// </summary>
    /// <param name="type">
    ///     This member specifies the type of credential to be created.
    ///     The value should be a member of <see cref="PublicKeyCredentialType" /> but client platforms must ignore unknown values,
    ///     ignoring any <see cref="PublicKeyCredentialParameters" /> with an unknown type.
    /// </param>
    /// <param name="alg">
    ///     This member specifies the cryptographic signature algorithm with which the newly generated credential will be used,
    ///     and thus also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
    /// </param>
    /// <exception cref="InvalidEnumArgumentException">
    ///     If the <paramref name="type" /> or <paramref name="alg" /> parameters
    ///     contain a value that is not defined in the <see cref="PublicKeyCredentialType" /> and <see cref="COSEAlgorithmIdentifier" /> enums, respectively.
    /// </exception>
    public PublicKeyCredentialParameters(PublicKeyCredentialType type, COSEAlgorithmIdentifier alg)
    {
        if (!Enum.IsDefined(typeof(PublicKeyCredentialType), type))
        {
            throw new InvalidEnumArgumentException(nameof(type), (int) type, typeof(PublicKeyCredentialType));
        }

        if (!Enum.IsDefined(typeof(COSEAlgorithmIdentifier), alg))
        {
            throw new InvalidEnumArgumentException(nameof(alg), (int) alg, typeof(COSEAlgorithmIdentifier));
        }

        Type = type;
        Alg = alg;
    }

    /// <summary>
    ///     This member specifies the type of credential to be created.
    ///     The value should be a member of <see cref="PublicKeyCredentialType" /> but client platforms must ignore unknown values,
    ///     ignoring any <see cref="PublicKeyCredentialParameters" /> with an unknown type.
    /// </summary>
    [Required]
    [JsonPropertyName("type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public PublicKeyCredentialType Type { get; }

    /// <summary>
    ///     This member specifies the cryptographic signature algorithm with which the newly generated credential will be used,
    ///     and thus also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
    /// </summary>
    [Required]
    [JsonPropertyName("alg")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public COSEAlgorithmIdentifier Alg { get; }
}
