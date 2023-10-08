using System;
using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models;

public class AttestationStatementVerificationResult
{
    public AttestationStatementVerificationResult(AttestationType attestationType)
    {
        if (!Enum.IsDefined(typeof(AttestationType), attestationType))
        {
            throw new InvalidEnumArgumentException(nameof(attestationType), (int) attestationType, typeof(AttestationType));
        }

        AttestationType = attestationType;
    }

    public AttestationStatementVerificationResult(AttestationType attestationType, X509Certificate2[] trustPath)
    {
        if (!Enum.IsDefined(typeof(AttestationType), attestationType))
        {
            throw new InvalidEnumArgumentException(nameof(attestationType), (int) attestationType, typeof(AttestationType));
        }

        ArgumentNullException.ThrowIfNull(trustPath);
        if (trustPath.Length == 0)
        {
            throw new ArgumentException("Value cannot be an empty collection.", nameof(trustPath));
        }

        AttestationType = attestationType;
        HasTrustPath = true;
        TrustPath = trustPath;
    }

    public AttestationType AttestationType { get; }

    public bool HasTrustPath { get; }

    public X509Certificate2[]? TrustPath { get; }
}
