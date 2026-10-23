using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;

namespace WebAuthn.Net.Services.Common.AttestationTrustPathValidator.Implementation;

public class DefaultAttestationTrustPathValidatorTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    // ---------------------------------------------------------------------------------------------
    // WebAuthn L3 §6.5.2: the attestation trust path "is either empty (in case of self attestation), or a set of X.509 certificates";
    // the packed self attestation (§8.2) and the none attestation statement format (§8.7) return an empty trust path, and §7.1 step 24 assesses them by the policy of the Relying Party only

    [TestCase(AttestationStatementFormat.Packed, AttestationType.Self)]
    [TestCase(AttestationStatementFormat.None, AttestationType.None)]
    public void IsValid_ReturnsTrue_ForSelfAndNoAttestationWithoutTrustPath(AttestationStatementFormat fmt, AttestationType attestationType)
    {
        var validator = new DefaultAttestationTrustPathValidator(new OptionsMonitorStub());

        var isValid = validator.IsValid(new(fmt, attestationType, null, null));

        Assert.That(isValid, Is.True);
    }

    [TestCase(AttestationStatementFormat.Packed, AttestationType.Self)]
    [TestCase(AttestationStatementFormat.None, AttestationType.None)]
    public void IsValid_ReturnsFalse_ForSelfAndNoAttestationWithSelfSignedCertificateAsTrustPath(AttestationStatementFormat fmt, AttestationType attestationType)
    {
        // a self-signed certificate made the self attestation valid before: it is not a trust path that the specification defines for these attestation types
        using var certificate = CreateSelfSigned("CN=WebAuthn.Net Self-Signed", false);
        var validator = new DefaultAttestationTrustPathValidator(new OptionsMonitorStub());

        var isValid = validator.IsValid(new(fmt, attestationType, new[] { certificate.RawData }, null));

        Assert.That(isValid, Is.False);
    }

    [TestCase(AttestationStatementFormat.Packed, AttestationType.Self)]
    [TestCase(AttestationStatementFormat.None, AttestationType.None)]
    public void IsValid_ReturnsFalse_ForSelfAndNoAttestationWhoseTrustPathIsTheirRootCertificate(AttestationStatementFormat fmt, AttestationType attestationType)
    {
        // the self attestation whose single certificate was its single root certificate (as the packed verifier returned for the "basic_surrogate" metadata) was valid before
        using var certificate = CreateSelfSigned("CN=WebAuthn.Net Self-Signed", false);
        var validator = new DefaultAttestationTrustPathValidator(new OptionsMonitorStub());

        var isValid = validator.IsValid(new(fmt, attestationType, new[] { certificate.RawData }, new UniqueByteArraysCollection(new[] { certificate.RawData })));

        Assert.That(isValid, Is.False);
    }

    // ---------------------------------------------------------------------------------------------
    // The other attestation types: the trust path must chain up to an acceptable root certificate (§7.1 step 24)

    [Test]
    public void IsValid_ReturnsTrue_ForBasicAttestation_WhenTrustPathChainsUpToRootCertificate()
    {
        using var root = CreateSelfSigned("CN=WebAuthn.Net Root", true);
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaf = new CertificateRequest("CN=WebAuthn.Net Attestation", leafKey, HashAlgorithmName.SHA256).Create(root, Now.AddDays(-1), Now.AddDays(30), new byte[] { 1, 2, 3, 4 });
        var validator = new DefaultAttestationTrustPathValidator(new OptionsMonitorStub());

        var isValid = validator.IsValid(new(AttestationStatementFormat.Packed, AttestationType.Basic, new[] { leaf.RawData }, new UniqueByteArraysCollection(new[] { root.RawData })));

        Assert.That(isValid, Is.True);
    }

    [Test]
    public void IsValid_ReturnsFalse_ForBasicAttestationWithoutTrustPath()
    {
        using var root = CreateSelfSigned("CN=WebAuthn.Net Root", true);
        var validator = new DefaultAttestationTrustPathValidator(new OptionsMonitorStub());

        var isValid = validator.IsValid(new(AttestationStatementFormat.Packed, AttestationType.Basic, null, new UniqueByteArraysCollection(new[] { root.RawData })));

        Assert.That(isValid, Is.False);
    }

    private static X509Certificate2 CreateSelfSigned(string subject, bool isCa)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        if (isCa)
        {
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        }

        return request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
    }

    private sealed class OptionsMonitorStub : IOptionsMonitor<WebAuthnOptions>
    {
        public WebAuthnOptions CurrentValue { get; } = new();

        public WebAuthnOptions Get(string? name)
        {
            return CurrentValue;
        }

        public IDisposable? OnChange(Action<WebAuthnOptions, string?> listener)
        {
            return null;
        }
    }
}
