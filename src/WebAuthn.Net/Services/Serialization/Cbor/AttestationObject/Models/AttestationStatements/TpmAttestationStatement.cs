using System;
using System.ComponentModel;
using System.Linq;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;

public class TpmAttestationStatement : AbstractAttestationStatement
{
    public TpmAttestationStatement(string ver, CoseAlgorithm alg, byte[][] x5C, byte[] sig, byte[] certInfo, byte[] pubArea)
    {
        if (string.IsNullOrEmpty(ver))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(ver));
        }

        if (!Enum.IsDefined(typeof(CoseAlgorithm), alg))
        {
            throw new InvalidEnumArgumentException(nameof(alg), (int) alg, typeof(CoseAlgorithm));
        }

        ArgumentNullException.ThrowIfNull(x5C);
        ArgumentNullException.ThrowIfNull(sig);
        ArgumentNullException.ThrowIfNull(certInfo);
        ArgumentNullException.ThrowIfNull(pubArea);
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (x5C.Any(static x => x is null))
        {
            throw new ArgumentException($"One or more objects contained in the '{nameof(x5C)}' array are equal to null.", nameof(x5C));
        }

        Ver = ver;
        Alg = alg;
        X5C = x5C;
        Sig = sig;
        CertInfo = certInfo;
        PubArea = pubArea;
    }

    public string Ver { get; }

    public CoseAlgorithm Alg { get; }

    public byte[][] X5C { get; }

    public byte[] Sig { get; }

    public byte[] CertInfo { get; }

    public byte[] PubArea { get; }


    public override TResult Accept<TResult>(IAttestationStatementVisitor<TResult> visitor)
    {
        ArgumentNullException.ThrowIfNull(visitor);
        return visitor.VisitTpmAttestationStatement(this);
    }
}
