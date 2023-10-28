namespace WebAuthn.Net.Services.RegistrationCeremony.Models.CreateCredential;

public class CompleteRegistrationCeremonyResult
{
    public CompleteRegistrationCeremonyResult(bool successful, bool requiringAdditionalAuthenticators)
    {
        Successful = successful;
        RequiringAdditionalAuthenticators = requiringAdditionalAuthenticators;
    }

    public bool Successful { get; }

    public bool RequiringAdditionalAuthenticators { get; }

    public static CompleteRegistrationCeremonyResult Success(bool requiringAdditionalAuthenticators)
    {
        return new(true, requiringAdditionalAuthenticators);
    }

    public static CompleteRegistrationCeremonyResult Fail()
    {
        return new(false, false);
    }
}
