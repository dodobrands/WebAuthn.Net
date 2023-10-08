namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Abstractions.Tpm;

public interface ITpmManufacturerVerifier
{
    bool IsValid(string tpmManufacturer);
}
