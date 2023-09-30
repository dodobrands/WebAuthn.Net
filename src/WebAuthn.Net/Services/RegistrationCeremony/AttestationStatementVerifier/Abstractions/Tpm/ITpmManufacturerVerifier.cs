namespace WebAuthn.Net.Services.RegistrationCeremony.Verification.Tpm;

public interface ITpmManufacturerVerifier
{
    bool IsValid(string tpmManufacturer);
}
