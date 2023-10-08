using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models;

/// <summary>
///     10.3.2 TPMT_HA
/// </summary>
public class TpmtHa
{
    public TpmtHa(TpmAlgIdHash hashAlg, byte[] digest)
    {
        HashAlg = hashAlg;
        Digest = digest;
    }

    // 10.3.2 TPMT_HA
    // Table 79 shows the basic hash-agile structure used in this specification.
    // To handle hash agility, this structure uses the hashAlg parameter to indicate the algorithm used to compute the digest and,
    // by implication, the size of the digest.
    // Table 79 — Definition of TPMT_HA Structure <IN/OUT>
    // | Parameter        | Type           | Description
    // | hashAlg          | +TPMI_ALG_HASH | selector of the hash contained in the digest that implies the size of the digest
    // | [hashAlg] digest | TPMU_HA        | the digest data

    public TpmAlgIdHash HashAlg { get; }

    public byte[] Digest { get; }
}
