using WebAuthn.Net.Configuration.Options.AttestationStatements;

namespace WebAuthn.Net.Configuration.Options;

public class AttestationStatementOptions
{
    public AndroidKeyAttestationStatementOptions AndroidKey { get; set; } = new();
}
