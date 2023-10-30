using System;
using WebAuthn.Net.Models;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;

public class AcceptableTrustAnchors
{
    public AcceptableTrustAnchors(UniqueByteArraysCollection attestationRootCertificates, byte[][]? attestationRootRsaPublicKeys)
    {
        // attestationRootCertificates
        ArgumentNullException.ThrowIfNull(attestationRootCertificates);
        if (attestationRootCertificates.Count < 1)
        {
            throw new ArgumentException($"The {nameof(attestationRootCertificates)} must contain at least one element", nameof(attestationRootCertificates));
        }

        AttestationRootCertificates = attestationRootCertificates;

        // attestationRootRsaPublicKeys
        if (attestationRootRsaPublicKeys?.Length > 0)
        {
            AttestationRootRsaPublicKeys = attestationRootRsaPublicKeys;
        }
    }

    public UniqueByteArraysCollection AttestationRootCertificates { get; }

    public byte[][]? AttestationRootRsaPublicKeys { get; }
}
