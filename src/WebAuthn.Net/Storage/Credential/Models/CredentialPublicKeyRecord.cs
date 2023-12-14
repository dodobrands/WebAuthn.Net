using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.Serialization.Cose.Models;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.Extensions;

namespace WebAuthn.Net.Storage.Credential.Models;

/// <summary>
///     Model for storing <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-public-key">credential public key</a> in COSE format.
/// </summary>
public class CredentialPublicKeyRecord
{
    /// <summary>
    ///     Constructs <see cref="CredentialPublicKeyRecord" />.
    /// </summary>
    /// <param name="kty">The key type defined by the "kty" member of a COSE_Key object.</param>
    /// <param name="alg">The identifier of the cryptographic algorithm of this public key.</param>
    /// <param name="rsa">Data about the public COSE key in RSA format.</param>
    /// <param name="ec2">Data about the public COSE key in EC2 format.</param>
    /// <param name="okp">Data about the public COSE key in OKP format.</param>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="kty" /> contains a value that is not defined in <see cref="CoseKeyType" /></exception>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="alg" /> contains a value that is not defined in <see cref="CoseAlgorithm" /></exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="alg" /> is not in the range of supported algorithms for public keys</exception>
    /// <exception cref="ArgumentNullException"><paramref name="rsa" /> is <see langword="null" /> when <paramref name="kty" /> contains <see cref="CoseKeyType.RSA" />.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="ec2" /> is <see langword="null" /> when <paramref name="kty" /> contains <see cref="CoseKeyType.EC2" />.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="okp" /> is <see langword="null" /> when <paramref name="kty" /> contains <see cref="CoseKeyType.OKP" />.</exception>
    public CredentialPublicKeyRecord(
        CoseKeyType kty,
        CoseAlgorithm alg,
        CredentialPublicKeyRsaParametersRecord? rsa,
        CredentialPublicKeyEc2ParametersRecord? ec2,
        CredentialPublicKeyOkpParametersRecord? okp)
    {
        // kty
        if (!Enum.IsDefined(typeof(CoseKeyType), kty))
        {
            throw new InvalidEnumArgumentException(nameof(kty), (int) kty, typeof(CoseKeyType));
        }

        Kty = kty;

        // alg
        if (!Enum.IsDefined(typeof(CoseAlgorithm), alg))
        {
            throw new InvalidEnumArgumentException(nameof(alg), (int) alg, typeof(CoseAlgorithm));
        }

        if (!kty.GetSupportedAlgorithms().Contains(alg))
        {
            throw new ArgumentOutOfRangeException(nameof(alg), $"The specified '{nameof(alg)}' is not included in the list of permitted values for kty = {kty:G}");
        }

        Alg = alg;

        // rsa
        if (kty == CoseKeyType.RSA)
        {
            ArgumentNullException.ThrowIfNull(rsa);
            Rsa = rsa;
        }

        // ec2
        if (kty == CoseKeyType.EC2)
        {
            ArgumentNullException.ThrowIfNull(ec2);
            if (!alg.TryGetEc2SupportedEllipticCurves(out var supportedCurves))
            {
                throw new ArgumentOutOfRangeException(nameof(alg), $"For the specified '{nameof(alg)}', there are no valid '{nameof(ec2)}.{nameof(ec2.Crv)}' values");
            }

            if (!supportedCurves.Contains(ec2.Crv))
            {
                throw new ArgumentOutOfRangeException(nameof(ec2), $"The specified '{nameof(ec2)}.{nameof(ec2.Crv)}' is not included in the list of valid values for '{nameof(alg)}'");
            }

            Ec2 = ec2;
        }

        // okp
        if (kty == CoseKeyType.OKP)
        {
            ArgumentNullException.ThrowIfNull(okp);
            if (!alg.TryGetOkpSupportedEllipticCurves(out var supportedCurves))
            {
                throw new ArgumentOutOfRangeException(nameof(alg), $"For the specified '{nameof(alg)}', there are no valid '{nameof(okp)}.{nameof(okp.Crv)}' values");
            }

            if (!supportedCurves.Contains(okp.Crv))
            {
                throw new ArgumentOutOfRangeException(nameof(okp), $"The specified '{nameof(okp)}.{nameof(okp.Crv)}' is not included in the list of valid values for '{nameof(alg)}'");
            }

            Okp = okp;
        }
    }

    /// <summary>
    ///     The key type defined by the "kty" member of a COSE_Key object.
    /// </summary>
    public CoseKeyType Kty { get; }

    /// <summary>
    ///     The identifier of the cryptographic algorithm of this public key.
    /// </summary>
    public CoseAlgorithm Alg { get; }

    /// <summary>
    ///     Data about the public COSE key in RSA format.
    /// </summary>
    public CredentialPublicKeyRsaParametersRecord? Rsa { get; }

    /// <summary>
    ///     Data about the public COSE key in EC2 format.
    /// </summary>
    public CredentialPublicKeyEc2ParametersRecord? Ec2 { get; }

    /// <summary>
    ///     Data about the public COSE key in OKP format.
    /// </summary>
    public CredentialPublicKeyOkpParametersRecord? Okp { get; }

    /// <summary>
    ///     If possible, converts the stored <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-public-key">credential public key</a> into a typed representation.
    /// </summary>
    /// <param name="key">Output parameter. The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-public-key">credential public key</a> materialized into a typed representation if the method returns <see langword="true" />, otherwise - <see langword="null" />.</param>
    /// <returns><see langword="true" /> if it was possible to convert the stored credential public key into a typed representation, otherwise - <see langword="false" />.</returns>
    public virtual bool TryToCoseKey([NotNullWhen(true)] out AbstractCoseKey? key)
    {
        switch (Kty)
        {
            case CoseKeyType.EC2:
                {
                    if (Ec2 is null)
                    {
                        key = null;
                        return false;
                    }

                    key = new CoseEc2Key(Alg, Ec2.Crv, Ec2.X, Ec2.Y);
                    return true;
                }
            case CoseKeyType.RSA:
                {
                    if (Rsa is null)
                    {
                        key = null;
                        return false;
                    }

                    key = new CoseRsaKey(Alg, Rsa.ModulusN, Rsa.ExponentE);
                    return true;
                }
            case CoseKeyType.OKP:
                {
                    if (Okp is null)
                    {
                        key = null;
                        return false;
                    }

                    key = new CoseOkpKey(Alg, Okp.Crv, Okp.X);
                    return true;
                }
            default:
                {
                    key = null;
                    return false;
                }
        }
    }
}
