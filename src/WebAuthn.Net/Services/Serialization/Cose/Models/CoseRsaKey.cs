﻿using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.Extensions;

namespace WebAuthn.Net.Services.Serialization.Cose.Models;

public class CoseRsaKey : AbstractCoseKey
{
    public CoseRsaKey(CoseAlgorithm alg, byte[] modulusN, byte[] exponentE)
    {
        if (!CoseKeyType.RSA.GetSupportedAlgorithms().Contains(alg))
        {
            throw new ArgumentOutOfRangeException(nameof(alg), "The specified 'alg' is not included in the list of permitted values for kty = RSA.");
        }

        ArgumentNullException.ThrowIfNull(modulusN);
        ArgumentNullException.ThrowIfNull(exponentE);
        Alg = alg;
        ModulusN = modulusN;
        ExponentE = exponentE;
    }

    public override CoseKeyType Kty => CoseKeyType.RSA;
    public override CoseAlgorithm Alg { get; }
    public byte[] ModulusN { get; }
    public byte[] ExponentE { get; }

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    public override bool Matches(X509Certificate2 certificate)
    {
        if (certificate is null)
        {
            return false;
        }

        using var certRsa = certificate.GetRSAPublicKey();
        if (certRsa is null)
        {
            return false;
        }

        var certParams = certRsa.ExportParameters(false);
        var certModulus = certParams.Modulus;
        var certExponent = certParams.Exponent;
        if (certModulus is null || certExponent is null)
        {
            return false;
        }

        return certModulus.AsSpan().SequenceEqual(ModulusN.AsSpan())
               && certExponent.AsSpan().SequenceEqual(ExponentE.AsSpan());
    }

    public override bool Matches(AsymmetricAlgorithm asymmetricAlgorithm)
    {
        if (asymmetricAlgorithm is not RSA alg)
        {
            return false;
        }

        var algParams = alg.ExportParameters(false);
        var algModulus = algParams.Modulus;
        var algExponent = algParams.Exponent;
        if (algModulus is null || algExponent is null)
        {
            return false;
        }

        return algModulus.AsSpan().SequenceEqual(ModulusN.AsSpan())
               && algExponent.AsSpan().SequenceEqual(ExponentE.AsSpan());
    }

    public override bool Matches(AbstractCoseKey coseKey)
    {
        if (coseKey is not CoseRsaKey other)
        {
            return false;
        }

        return other.Kty == Kty
               && other.Alg == Alg
               && other.ModulusN.AsSpan().SequenceEqual(ModulusN.AsSpan())
               && other.ExponentE.AsSpan().SequenceEqual(ExponentE.AsSpan());
    }
}