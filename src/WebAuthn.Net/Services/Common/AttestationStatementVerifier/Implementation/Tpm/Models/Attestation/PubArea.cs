using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation;

/// <summary>
///     The TPMT_PUBLIC structure (see <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">[TPMv2-Part2]</a> section 12.2.4) used by the TPM to represent the credential public key.
/// </summary>
public class PubArea
{
    public PubArea(
        TpmAlgPublic type,
        TpmAlgIdHash nameAlg,
        ObjectAttributes objectAttributes,
        AbstractPublicParms parameters,
        AbstractUnique unique)
    {
        Type = type;
        NameAlg = nameAlg;
        ObjectAttributes = objectAttributes;
        Parameters = parameters;
        Unique = unique;
    }

    public TpmAlgPublic Type { get; }

    public TpmAlgIdHash NameAlg { get; }

    public ObjectAttributes ObjectAttributes { get; }

    public AbstractPublicParms Parameters { get; }

    public AbstractUnique Unique { get; }
}
