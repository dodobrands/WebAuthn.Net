using System;
using System.ComponentModel;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;

/// <summary>
///     Parameters for Credential Generation (dictionary PublicKeyCredentialParameters)
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-credential-params">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.3. Parameters for Credential Generation (dictionary PublicKeyCredentialParameters)</a>
///     </para>
/// </remarks>
public class PublicKeyCredentialParameters
{
    /// <summary>
    ///     Constructs <see cref="PublicKeyCredentialParameters" />.
    /// </summary>
    /// <param name="type">
    ///     This member specifies the type of credential to be created. The value SHOULD be a member of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialtype">PublicKeyCredentialType</a> but
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore unknown values, ignoring any <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictdef-publickeycredentialparameters">PublicKeyCredentialParameters</a>
    ///     with an unknown <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialparameters-type">type</a>.
    /// </param>
    /// <param name="alg">This member specifies the cryptographic signature algorithm with which the newly generated credential will be used, and thus also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.</param>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="type" /> contains a value that is not defined in <see cref="PublicKeyCredentialType" /></exception>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="alg" /> contains a value that is not defined in <see cref="CoseAlgorithm" /></exception>
    public PublicKeyCredentialParameters(PublicKeyCredentialType type, CoseAlgorithm alg)
    {
        if (!Enum.IsDefined(typeof(PublicKeyCredentialType), type))
        {
            throw new InvalidEnumArgumentException(nameof(type), (int) type, typeof(PublicKeyCredentialType));
        }

        if (!Enum.IsDefined(typeof(CoseAlgorithm), alg))
        {
            throw new InvalidEnumArgumentException(nameof(alg), (int) alg, typeof(CoseAlgorithm));
        }

        Type = type;
        Alg = alg;
    }

    /// <summary>
    ///     This member specifies the type of credential to be created. The value SHOULD be a member of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialtype">PublicKeyCredentialType</a> but
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore unknown values, ignoring any <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictdef-publickeycredentialparameters">PublicKeyCredentialParameters</a>
    ///     with an unknown <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialparameters-type">type</a>.
    /// </summary>
    public PublicKeyCredentialType Type { get; }

    /// <summary>
    ///     This member specifies the cryptographic signature algorithm with which the newly generated credential will be used, and thus also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
    /// </summary>
    /// <remarks>
    ///     We use "alg" as the latter member name, rather than spelling-out "algorithm", because it will be serialized into a message to the authenticator, which may be sent over a low-bandwidth link.
    /// </remarks>
    public CoseAlgorithm Alg { get; }
}
