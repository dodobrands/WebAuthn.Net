using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;

namespace WebAuthn.Net.Services.Common.AttestationTrustPathValidator.Implementation;

public class DefaultAttestationTrustPathValidatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    // RFC 5280 §4.2.1.1: in a self-signed certificate the keyIdentifier of the Authority Key Identifier equals the Subject Key Identifier -
    // the decoded identifiers must be compared, not the raw extension values (SEQUENCE { [0] keyIdentifier } vs OCTET STRING), which never match
    [Test]
    public void IsSelfSigned_ReturnsTrue_ForSelfSignedCertificateWithMatchingAuthorityAndSubjectKeyIdentifiers()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=WebAuthn.Net Self-Signed", key, HashAlgorithmName.SHA256);
        var subjectKeyIdentifier = new X509SubjectKeyIdentifierExtension(request.PublicKey, false);
        request.CertificateExtensions.Add(subjectKeyIdentifier);
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(subjectKeyIdentifier));
        using var certificate = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
        var validator = new TestTrustPathValidator();

        Assert.That(validator.IsSelfSignedCertificate(certificate.RawData), Is.True);
    }

    [Test]
    public void IsSelfSigned_ReturnsTrue_ForSelfSignedCertificateWithoutKeyIdentifiers()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=WebAuthn.Net Self-Signed", key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
        var validator = new TestTrustPathValidator();

        Assert.That(validator.IsSelfSignedCertificate(certificate.RawData), Is.True);
    }

    [Test]
    public void IsSelfSigned_ReturnsFalse_WhenAuthorityKeyIdentifierNamesAnotherKey()
    {
        // subject == issuer, but the Authority Key Identifier points to another key
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=WebAuthn.Net Self-Signed", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var otherRequest = new CertificateRequest("CN=Other", otherKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(new X509SubjectKeyIdentifierExtension(otherRequest.PublicKey, false)));
        using var certificate = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
        var validator = new TestTrustPathValidator();

        Assert.That(validator.IsSelfSignedCertificate(certificate.RawData), Is.False);
    }

    [Test]
    public void IsSelfSigned_ReturnsFalse_ForCertificateIssuedByAnotherCertificate()
    {
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var issuerRequest = new CertificateRequest("CN=WebAuthn.Net Issuer", issuerKey, HashAlgorithmName.SHA256);
        issuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var issuer = issuerRequest.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=WebAuthn.Net Leaf", key, HashAlgorithmName.SHA256);
        using var certificate = request.Create(issuer, Now.AddDays(-1), Now.AddDays(30), new byte[] { 1, 2, 3, 4 });
        var validator = new TestTrustPathValidator();

        Assert.That(validator.IsSelfSignedCertificate(certificate.RawData), Is.False);
    }

    [Test]
    public void IsSelfSigned_ReturnsFalse_WithoutException_WhenCertificateCannotBeLoaded()
    {
        var validator = new TestTrustPathValidator();
        var isSelfSigned = true;

        Assert.DoesNotThrow(() => isSelfSigned = validator.IsSelfSignedCertificate(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 }));

        Assert.That(isSelfSigned, Is.False);
    }

    [Test]
    public void IsValid_ReturnsTrue_ForSelfAttestation_WhenTrustPathIsSingleSelfSignedCertificateAndThereAreNoRoots()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("C=SE, O=WebAuthn.Net, OU=Authenticator Attestation, CN=WebAuthn.Net Self-Signed Attestation", key, HashAlgorithmName.SHA256);
        var subjectKeyIdentifier = new X509SubjectKeyIdentifierExtension(request.PublicKey, false);
        request.CertificateExtensions.Add(subjectKeyIdentifier);
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(subjectKeyIdentifier));
        using var certificate = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
        var validator = new TestTrustPathValidator();

        var isValid = validator.IsValid(new(AttestationStatementFormat.Packed, AttestationType.Self, new[] { certificate.RawData }, null));

        Assert.That(isValid, Is.True);
    }

    private sealed class TestTrustPathValidator : DefaultAttestationTrustPathValidator
    {
        public TestTrustPathValidator() : base(new OptionsMonitorStub())
        {
        }

        public bool IsSelfSignedCertificate(byte[] certificate)
        {
            return IsSelfSigned(certificate);
        }
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
