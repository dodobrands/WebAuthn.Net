using System;
using System.Linq;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementDecoder.Models.AttestationStatements;

public class FidoU2FAttestationStatement : AbstractAttestationStatement
{
    public FidoU2FAttestationStatement(byte[] sig, byte[][] x5C)
    {
        ArgumentNullException.ThrowIfNull(sig);
        ArgumentNullException.ThrowIfNull(x5C);

        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (x5C.Any(static x => x is null))
        {
            throw new ArgumentException($"One or more objects contained in the {nameof(x5C)} array are equal to null.", nameof(x5C));
        }

        Sig = sig;
        X5C = x5C;
    }

    public byte[] Sig { get; }

    public byte[][] X5C { get; }
}
