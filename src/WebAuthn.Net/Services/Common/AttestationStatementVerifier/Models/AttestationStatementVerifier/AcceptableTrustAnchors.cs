using System;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;

public class AcceptableTrustAnchors
{
    public AcceptableTrustAnchors(byte[][] attestationRootCertificates, byte[][]? attestationRootRsaPublicKeys)
    {
        // attestationRootCertificates
        ArgumentNullException.ThrowIfNull(attestationRootCertificates);
        if (attestationRootCertificates.Length < 1)
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

    public byte[][] AttestationRootCertificates { get; }

    public byte[][]? AttestationRootRsaPublicKeys { get; }
}
