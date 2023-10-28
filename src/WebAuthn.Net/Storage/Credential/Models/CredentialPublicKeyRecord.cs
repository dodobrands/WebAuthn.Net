using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.Cryptography.Cose.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.Extensions;

namespace WebAuthn.Net.Storage.Credential.Models;

/// <summary>
///     https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-public-key
/// </summary>
public class CredentialPublicKeyRecord
{
    public CredentialPublicKeyRecord(
        CoseKeyType kty,
        CoseAlgorithm alg,
        CredentialPublicKeyRsaParametersRecord? rsa,
        CredentialPublicKeyEc2ParametersRecord? ec2)
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
            if (!alg.TryGetSupportedEllipticCurves(out var supportedCurves))
            {
                throw new ArgumentOutOfRangeException(nameof(alg), $"For the specified '{nameof(alg)}', there are no valid '{nameof(ec2)}.{nameof(ec2.Crv)}' values");
            }

            if (!supportedCurves.Contains(ec2.Crv))
            {
                throw new ArgumentOutOfRangeException(nameof(ec2), $"The specified '{nameof(ec2)}.{nameof(ec2.Crv)}' is not included in the list of valid values for '{nameof(alg)}'");
            }

            Ec2 = ec2;
        }
    }

    public CoseKeyType Kty { get; }
    public CoseAlgorithm Alg { get; }
    public CredentialPublicKeyRsaParametersRecord? Rsa { get; }
    public CredentialPublicKeyEc2ParametersRecord? Ec2 { get; }

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
            default:
                {
                    key = null;
                    return false;
                }
        }
    }
}
