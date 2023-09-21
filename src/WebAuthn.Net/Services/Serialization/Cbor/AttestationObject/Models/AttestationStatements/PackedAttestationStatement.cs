using System;
using System.ComponentModel;
using System.Linq;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;

public class PackedAttestationStatement : AbstractAttestationStatement
{
    public PackedAttestationStatement(CoseAlgorithmIdentifier alg, byte[] sig, byte[][]? x5C)
    {
        if (!Enum.IsDefined(typeof(CoseAlgorithmIdentifier), alg))
        {
            throw new InvalidEnumArgumentException(nameof(alg), (int) alg, typeof(CoseAlgorithmIdentifier));
        }

        ArgumentNullException.ThrowIfNull(sig);
        if (x5C is not null)
        {
            // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
            if (x5C.Any(static x => x is null))
            {
                throw new ArgumentException($"One or more objects contained in the '{nameof(x5C)}' array are equal to null.", nameof(x5C));
            }

            X5C = x5C;
        }

        Alg = alg;
        Sig = sig;
    }

    public CoseAlgorithmIdentifier Alg { get; }

    public byte[] Sig { get; }

    public byte[][]? X5C { get; }

    public override TResult Accept<TResult>(IAttestationStatementVisitor<TResult> visitor)
    {
        ArgumentNullException.ThrowIfNull(visitor);
        return visitor.VisitPackedAttestationStatement(this);
    }
}
