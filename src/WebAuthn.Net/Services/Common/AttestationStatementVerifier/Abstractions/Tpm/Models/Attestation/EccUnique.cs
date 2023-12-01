using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Abstractions;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     11.2.5.2 TPMS_ECC_POINT
/// </summary>
public class EccUnique : AbstractUnique
{
    public EccUnique(byte[] x, byte[] y)
    {
        X = x;
        Y = y;
    }

    public byte[] X { get; }
    public byte[] Y { get; }
}
