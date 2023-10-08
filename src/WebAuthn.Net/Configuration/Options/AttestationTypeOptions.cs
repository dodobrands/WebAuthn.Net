using WebAuthn.Net.Configuration.Options.AttestationTypes;

namespace WebAuthn.Net.Configuration.Options;

public class AttestationTypeOptions
{
    public NoneAttestationTypeOptions None { get; set; } = new();
    public SelfAttestationOptions Self { get; set; } = new();
}
