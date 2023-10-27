namespace WebAuthn.Net.Services.RegistrationCeremony.Models.CreateCredential;

public class CompleteRegistrationCeremonyResult
{
    public CompleteRegistrationCeremonyResult(bool successful)
    {
        Successful = successful;
    }

    public bool Successful { get; }
}
