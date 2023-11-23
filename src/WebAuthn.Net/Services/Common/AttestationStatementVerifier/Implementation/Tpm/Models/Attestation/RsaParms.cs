using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation.Abstractions;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation;

/// <summary>
///     12.2.3.5 TPMS_RSA_PARMS
/// </summary>
public class RsaParms : AbstractPublicParms
{
    public RsaParms(ushort keyBits, uint exponent)
    {
        KeyBits = keyBits;
        Exponent = exponent;
    }

    public ushort KeyBits { get; }
    public uint Exponent { get; }
}
