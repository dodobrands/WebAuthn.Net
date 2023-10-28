using System;
using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Models.Manufacturer;

public class TpmManufacturerVerificationResult
{
    public TpmManufacturerVerificationResult(bool isValid, byte[][]? rootCerts)
    {
        IsValid = isValid;
        if (isValid)
        {
            if (rootCerts is null)
            {
                ArgumentNullException.ThrowIfNull(rootCerts);
            }

            RootCerts = rootCerts;
        }
    }

    [MemberNotNullWhen(true, nameof(RootCerts))]
    public bool IsValid { get; }

    public byte[][]? RootCerts { get; }
}
