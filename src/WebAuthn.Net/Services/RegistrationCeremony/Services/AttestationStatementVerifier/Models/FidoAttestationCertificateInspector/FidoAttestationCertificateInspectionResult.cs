using System;
using System.ComponentModel;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models.FidoAttestationCertificateInspector;

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
