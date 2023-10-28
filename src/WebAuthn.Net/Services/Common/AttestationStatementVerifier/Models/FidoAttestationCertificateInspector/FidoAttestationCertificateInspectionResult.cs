using System;
using System.ComponentModel;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.FidoAttestationCertificateInspector;

public class FidoAttestationCertificateInspectionResult
{
    public FidoAttestationCertificateInspectionResult(AttestationType attestationType, AcceptableTrustAnchors acceptableTrustAnchors)
    {
        if (!Enum.IsDefined(typeof(AttestationType), attestationType))
        {
            throw new InvalidEnumArgumentException(nameof(attestationType), (int) attestationType, typeof(AttestationType));
        }


        AttestationType = attestationType;
        AcceptableTrustAnchors = acceptableTrustAnchors;
    }

    public AttestationType AttestationType { get; }
    public AcceptableTrustAnchors? AcceptableTrustAnchors { get; }
}
