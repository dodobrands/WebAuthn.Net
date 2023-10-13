using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Manufacturer;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Abstractions.Tpm;

public interface ITpmManufacturerVerifier
{
    TpmManufacturerVerificationResult IsValid(string tpmManufacturer);
}
