using System;
using System.ComponentModel;
using System.Linq;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;

public class PackedAttestationStatement : AbstractAttestationStatement
{
    public PackedAttestationStatement(CoseAlgorithm alg, byte[] sig, byte[][]? x5C)
    {
        if (!Enum.IsDefined(typeof(CoseAlgorithm), alg))
        {
            throw new InvalidEnumArgumentException(nameof(alg), (int) alg, typeof(CoseAlgorithm));
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

    public CoseAlgorithm Alg { get; }

    public byte[] Sig { get; }

    public byte[][]? X5C { get; }
}
