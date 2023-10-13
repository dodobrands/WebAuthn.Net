using System.Security.Cryptography.X509Certificates;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Manufacturer;

public class TpmManufacturerVerificationResult
{
    public TpmManufacturerVerificationResult(bool isValid, X509Certificate2[]? rootCerts)
    {
        IsValid = isValid;
        RootCerts = rootCerts;
    }

    public bool IsValid { get; }

    public X509Certificate2[]? RootCerts { get; }
}
