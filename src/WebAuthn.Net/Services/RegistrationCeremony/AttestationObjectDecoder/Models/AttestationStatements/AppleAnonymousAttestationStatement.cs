using System;
using System.Linq;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements.Abstractions;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements;

public class AppleAnonymousAttestationStatement : AbstractAttestationStatement
{
    public AppleAnonymousAttestationStatement(byte[][] x5C)
    {
        ArgumentNullException.ThrowIfNull(x5C);
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (x5C.Any(static x => x is null))
        {
            throw new ArgumentException($"One or more objects contained in the {nameof(x5C)} array are equal to null.", nameof(x5C));
        }

        X5C = x5C;
    }

    public byte[][] X5C { get; }
}
