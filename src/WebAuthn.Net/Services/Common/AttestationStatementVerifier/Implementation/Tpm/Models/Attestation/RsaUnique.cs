using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation.Abstractions;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation;

/// <summary>
///     11.2.4.5 TPM2B_PUBLIC_KEY_RSA
/// </summary>
public class RsaUnique : AbstractUnique
{
    public RsaUnique(byte[] buffer)
    {
        Buffer = buffer;
    }

    public byte[] Buffer { get; }
}
