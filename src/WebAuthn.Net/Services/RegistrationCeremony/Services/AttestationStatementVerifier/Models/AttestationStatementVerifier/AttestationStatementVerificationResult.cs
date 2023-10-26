using System;
using System.ComponentModel;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models.AttestationStatementVerifier;

public class AttestationStatementVerificationResult
{
    public AttestationStatementVerificationResult(
        AttestationStatementFormat fmt,
        AttestationType attestationType,
        byte[][]? attestationTrustPath,
        AcceptableTrustAnchors? acceptableTrustAnchors)
    {
        // fmt
        if (!Enum.IsDefined(typeof(AttestationStatementFormat), fmt))
        {
            throw new InvalidEnumArgumentException(nameof(fmt), (int) fmt, typeof(AttestationStatementFormat));
        }

        Fmt = fmt;

        // attestationType
        if (!Enum.IsDefined(typeof(AttestationType), attestationType))
        {
            throw new InvalidEnumArgumentException(nameof(attestationType), (int) attestationType, typeof(AttestationType));
        }

        AttestationType = attestationType;

        // attestationTrustPath
        if (attestationTrustPath?.Length > 0)
        {
            AttestationTrustPath = attestationTrustPath;
        }

        // acceptableTrustAnchors
        AcceptableTrustAnchors = acceptableTrustAnchors;
    }

    public AttestationStatementFormat Fmt { get; }
    public AttestationType AttestationType { get; }
    public byte[][]? AttestationTrustPath { get; }
    public AcceptableTrustAnchors? AcceptableTrustAnchors { get; }
}
