namespace WebAuthn.Net.Storage.Operations.Models;

public class RegistrationCeremonyOptions
{
    public RegistrationCeremonyOptions(byte[] challenge)
    {
        Challenge = challenge;
    }

    public byte[] Challenge { get; }
}
