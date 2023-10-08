using System;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models.AttestationStatements.Abstractions;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models.AttestationStatements;

public class AndroidSafetyNetAttestationStatement : AbstractAttestationStatement
{
    public AndroidSafetyNetAttestationStatement(string ver, byte[] response)
    {
        if (string.IsNullOrEmpty(ver))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(ver));
        }

        ArgumentNullException.ThrowIfNull(response);

        Ver = ver;
        Response = response;
    }

    public string Ver { get; }

    public byte[] Response { get; }
}
