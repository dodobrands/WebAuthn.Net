using System;
using System.ComponentModel;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models;

public class AttestationStatementVerificationResult
{
    public AttestationStatementVerificationResult(
        AttestationStatementFormat fmt,
        AttestationType attestationType)
    {
        if (!Enum.IsDefined(typeof(AttestationStatementFormat), fmt))
        {
            throw new InvalidEnumArgumentException(nameof(fmt), (int) fmt, typeof(AttestationStatementFormat));
        }

        if (!Enum.IsDefined(typeof(AttestationType), attestationType))
        {
            throw new InvalidEnumArgumentException(nameof(attestationType), (int) attestationType, typeof(AttestationType));
        }

        Fmt = fmt;
        AttestationType = attestationType;
    }

    public AttestationStatementVerificationResult(
        AttestationStatementFormat fmt,
        AttestationType attestationType,
        byte[][] trustPath,
        byte[][]? rootCertificates)
    {
        if (!Enum.IsDefined(typeof(AttestationStatementFormat), fmt))
        {
            throw new InvalidEnumArgumentException(nameof(fmt), (int) fmt, typeof(AttestationStatementFormat));
        }

        if (!Enum.IsDefined(typeof(AttestationType), attestationType))
        {
            throw new InvalidEnumArgumentException(nameof(attestationType), (int) attestationType, typeof(AttestationType));
        }

        ArgumentNullException.ThrowIfNull(trustPath);
        if (trustPath.Length == 0)
        {
            throw new ArgumentException("Value cannot be an empty collection.", nameof(trustPath));
        }

        Fmt = fmt;
        AttestationType = attestationType;
        TrustPath = trustPath;
        RootCertificates = rootCertificates;
    }

    public AttestationStatementFormat Fmt { get; }

    public AttestationType AttestationType { get; }

    public byte[][]? TrustPath { get; }
    public byte[][]? RootCertificates { get; }
}
