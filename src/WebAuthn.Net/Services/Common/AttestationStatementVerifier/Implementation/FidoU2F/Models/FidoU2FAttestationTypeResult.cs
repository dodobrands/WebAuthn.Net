using System;
using System.ComponentModel;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.FidoU2F.Models;

public class FidoU2FAttestationTypeResult
{
    public FidoU2FAttestationTypeResult(
        AttestationType attestationType,
        UniqueByteArraysCollection attestationRootCertificates)
    {
        if (!Enum.IsDefined(typeof(AttestationType), attestationType))
        {
            throw new InvalidEnumArgumentException(nameof(attestationType), (int) attestationType, typeof(AttestationType));
        }

        ArgumentNullException.ThrowIfNull(attestationRootCertificates);
        if (attestationRootCertificates.Count == 0)
        {
            throw new ArgumentException($"The {nameof(attestationRootCertificates)} must contain at least one element", nameof(attestationRootCertificates));
        }

        AttestationType = attestationType;
        AttestationRootCertificates = attestationRootCertificates;
    }

    public AttestationType AttestationType { get; }
    public UniqueByteArraysCollection AttestationRootCertificates { get; }
}
