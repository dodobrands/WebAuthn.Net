using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Manufacturer;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;

public interface ITpmManufacturerVerifier
{
    TpmManufacturerVerificationResult IsValid(string tpmManufacturer);
}
