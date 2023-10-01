namespace WebAuthn.Net.Configuration.Options;

public class RegistrationOptions
{
    public AndroidKeyAttestationOptions AndroidKeyAttestation { get; set; } = new();
}
