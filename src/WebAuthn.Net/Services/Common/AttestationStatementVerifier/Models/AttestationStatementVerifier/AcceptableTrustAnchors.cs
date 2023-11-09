using System;
using WebAuthn.Net.Models;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;

public class AcceptableTrustAnchors
{
    public AcceptableTrustAnchors(UniqueByteArraysCollection attestationRootCertificates)
    {
        // attestationRootCertificates
        ArgumentNullException.ThrowIfNull(attestationRootCertificates);
        if (attestationRootCertificates.Count == 0)
        {
            throw new ArgumentException($"The {nameof(attestationRootCertificates)} must contain at least one element", nameof(attestationRootCertificates));
        }

        AttestationRootCertificates = attestationRootCertificates;
    }

    public UniqueByteArraysCollection AttestationRootCertificates { get; }
}
