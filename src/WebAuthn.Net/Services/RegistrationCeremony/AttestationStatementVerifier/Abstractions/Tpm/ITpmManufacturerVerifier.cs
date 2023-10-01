namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.Tpm;

public interface ITpmManufacturerVerifier
{
    bool IsValid(string tpmManufacturer);
}
