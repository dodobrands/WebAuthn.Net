using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Configuration.Options.AttestationTypes;

[SuppressMessage("Performance", "CA1805:Do not initialize unnecessarily")]
public class SelfAttestationOptions
{
    public bool IsAcceptable { get; set; } = false;
}
