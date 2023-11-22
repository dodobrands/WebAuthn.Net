namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation;

/// <summary>
///     10.5.3 TPM2B_NAME
/// </summary>
public class Tpm2BName
{
    public Tpm2BName(TpmtHa? digest, TpmHandle? handle)
    {
        Digest = digest;
        Handle = handle;
    }

    public TpmtHa? Digest { get; }

    public TpmHandle? Handle { get; }
}
