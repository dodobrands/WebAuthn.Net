using System;
using System.ComponentModel;
using System.Linq;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements.Abstractions;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements;

public class AppleAnonymousAttestationStatement : AbstractAttestationStatement
{
    public AppleAnonymousAttestationStatement(CoseAlgorithm alg, byte[][] x5C)
    {
        if (!Enum.IsDefined(typeof(CoseAlgorithm), alg))
        {
            throw new InvalidEnumArgumentException(nameof(alg), (int) alg, typeof(CoseAlgorithm));
        }

        ArgumentNullException.ThrowIfNull(x5C);
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (x5C.Any(static x => x is null))
        {
            throw new ArgumentException($"One or more objects contained in the {nameof(x5C)} array are equal to null.", nameof(x5C));
        }

        Alg = alg;
        X5C = x5C;
    }

    public CoseAlgorithm Alg { get; }

    public byte[][] X5C { get; }
}
