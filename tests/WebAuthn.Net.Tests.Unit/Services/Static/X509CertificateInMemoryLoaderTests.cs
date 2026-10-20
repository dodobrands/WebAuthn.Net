using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;

namespace WebAuthn.Net.Services.Static;

public class X509CertificateInMemoryLoaderTests
{
    private static readonly byte[] EmptyName = { 0x30, 0x00 };
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Test]
    public void TryLoad_ReturnsCertificate_WhenCertificateIsWellFormed()
    {
        var bytes = BuildCertificate(null);

        var loaded = X509CertificateInMemoryLoader.TryLoad(bytes, out var certificate);
        using (certificate)
        {
            Assert.Multiple(() =>
            {
                Assert.That(loaded, Is.True);
                Assert.That(certificate, Is.Not.Null);
                Assert.That(certificate!.NotBefore, Is.LessThan(certificate.NotAfter));
            });
        }
    }

    // UTCTime values that do not follow RFC 5280 §4.1.2.5.1 (YYMMDDHHMMSSZ): macOS refuses to load such a certificate,
    // Linux loads it and throws CryptographicException only when NotBefore / NotAfter is read - TryLoad must return false on both
    [TestCase("261301000000Z")] // month 13
    [TestCase("260230000000Z")] // February 30
    [TestCase("260101250000Z")] // hour 25
    [TestCase("2601010000Z")] // no seconds
    [TestCase("260101000000+0100")] // not in UTC
    public void TryLoad_ReturnsFalse_WithoutException_WhenValidityTimeIsMalformed(string notBefore)
    {
        var bytes = BuildCertificate(Validity(notBefore, "301231235959Z"));

        var loaded = true;
        X509Certificate2? certificate = null;
        Assert.DoesNotThrow(() => loaded = X509CertificateInMemoryLoader.TryLoad(bytes, out certificate));
        using (certificate)
        {
            Assert.Multiple(() =>
            {
                Assert.That(loaded, Is.False);
                Assert.That(certificate, Is.Null);
            });
        }
    }

    [Test]
    public void TryLoad_ReturnsFalse_WhenBytesAreNotCertificate()
    {
        var loaded = X509CertificateInMemoryLoader.TryLoad(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 }, out var certificate);
        using (certificate)
        {
            Assert.Multiple(() =>
            {
                Assert.That(loaded, Is.False);
                Assert.That(certificate, Is.Null);
            });
        }
    }

    // Only a single X.509 certificate is acceptable: on net8.0 the X509Certificate2 constructor would otherwise accept a PKCS#12 container
    // and run its key-derivation function (with an attacker-chosen iteration count) before anything is verified
    [Test]
    public void TryLoad_ReturnsFalse_WithoutException_WhenBytesArePkcs12Container()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=WebAuthn.Net PKCS#12", key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
        var pkcs12 = certificate.Export(X509ContentType.Pkcs12);
        Assert.That(X509Certificate2.GetCertContentType(pkcs12), Is.EqualTo(X509ContentType.Pkcs12), "precondition: the bytes are a PKCS#12 container");

        var loaded = true;
        X509Certificate2? loadedCertificate = null;
        Assert.DoesNotThrow(() => loaded = X509CertificateInMemoryLoader.TryLoad(pkcs12, out loadedCertificate));
        using (loadedCertificate)
        {
            Assert.Multiple(() =>
            {
                Assert.That(loaded, Is.False);
                Assert.That(loadedCertificate, Is.Null);
            });
        }
    }

    [Test]
    public void TryLoad_ReturnsFalse_WithoutException_WhenBytesArePkcs7Container()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=WebAuthn.Net PKCS#7", key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
        var pkcs7 = new X509Certificate2Collection(certificate).Export(X509ContentType.Pkcs7);
        Assert.That(pkcs7, Is.Not.Null);
        Assert.That(X509Certificate2.GetCertContentType(pkcs7!), Is.EqualTo(X509ContentType.Pkcs7), "precondition: the bytes are a PKCS#7 container");

        var loaded = true;
        X509Certificate2? loadedCertificate = null;
        Assert.DoesNotThrow(() => loaded = X509CertificateInMemoryLoader.TryLoad(pkcs7!, out loadedCertificate));
        using (loadedCertificate)
        {
            Assert.Multiple(() =>
            {
                Assert.That(loaded, Is.False);
                Assert.That(loadedCertificate, Is.Null);
            });
        }
    }

    // The platforms do not validate extension values when loading; the typed extensions of X509Certificate2.Extensions decode them lazily and throw on the first property access -
    // TryLoad must reject such certificates so that the verifiers never throw on client-supplied certificates
    // (the certificates are written directly as DER: CertificateRequest loads the certificate it creates, and the platforms differ in what they refuse)
    [TestCase("2.5.29.19", new byte[] { 0x05, 0x00 }, TestName = "TryLoad_ReturnsFalse_WithoutException_WhenTypedExtensionValueIsMalformed(Basic Constraints: NULL)")]
    [TestCase("2.5.29.19", new byte[] { 0x30, 0x02, 0x05, 0x00 }, TestName = "TryLoad_ReturnsFalse_WithoutException_WhenTypedExtensionValueIsMalformed(Basic Constraints: NULL instead of BOOLEAN)")]
    [TestCase("2.5.29.14", new byte[] { 0x30, 0x00 }, TestName = "TryLoad_ReturnsFalse_WithoutException_WhenTypedExtensionValueIsMalformed(Subject Key Identifier: SEQUENCE)")]
    [TestCase("2.5.29.15", new byte[] { 0x04, 0x01, 0x00 }, TestName = "TryLoad_ReturnsFalse_WithoutException_WhenTypedExtensionValueIsMalformed(Key Usage: OCTET STRING)")]
    [TestCase("2.5.29.37", new byte[] { 0x02, 0x01, 0x01 }, TestName = "TryLoad_ReturnsFalse_WithoutException_WhenTypedExtensionValueIsMalformed(Extended Key Usage: INTEGER)")]
    [TestCase("2.5.29.37", new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 }, TestName = "TryLoad_ReturnsFalse_WithoutException_WhenTypedExtensionValueIsMalformed(Extended Key Usage: SEQUENCE of INTEGER)")]
    [TestCase("2.5.29.35", new byte[] { 0x04, 0x00 }, TestName = "TryLoad_ReturnsFalse_WithoutException_WhenTypedExtensionValueIsMalformed(Authority Key Identifier: OCTET STRING)")]
    [TestCase("2.5.29.35", new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 }, TestName = "TryLoad_ReturnsFalse_WithoutException_WhenTypedExtensionValueIsMalformed(Authority Key Identifier: SEQUENCE of INTEGER)")]
    public void TryLoad_ReturnsFalse_WithoutException_WhenTypedExtensionValueIsMalformed(string oid, byte[] value)
    {
        var bytes = BuildCertificate(null, (oid, false, value));

        var loaded = true;
        X509Certificate2? loadedCertificate = null;
        Assert.DoesNotThrow(() => loaded = X509CertificateInMemoryLoader.TryLoad(bytes, out loadedCertificate));
        using (loadedCertificate)
        {
            Assert.Multiple(() =>
            {
                Assert.That(loaded, Is.False);
                Assert.That(loadedCertificate, Is.Null);
            });
        }
    }

    [Test]
    public void TryLoad_ReturnsCertificate_WhenDirectlyWrittenCertificateHasWellFormedTypedExtensions()
    {
        // the same DER writer as the malformed cases, with well-formed values: proves that the rejections above are caused by the values, not by the writer
        var bytes = BuildCertificate(
            null,
            ("2.5.29.19", true, new byte[] { 0x30, 0x00 }), // Basic Constraints: cA absent (FALSE)
            ("2.5.29.15", true, new byte[] { 0x03, 0x02, 0x07, 0x80 }), // Key Usage: digitalSignature
            ("2.5.29.37", false, new byte[] { 0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 }), // Extended Key Usage: id-kp-clientAuth
            ("2.5.29.14", false, new byte[] { 0x04, 0x04, 0x01, 0x02, 0x03, 0x04 }), // Subject Key Identifier
            ("2.5.29.35", false, new byte[] { 0x30, 0x06, 0x80, 0x04, 0x01, 0x02, 0x03, 0x04 })); // Authority Key Identifier: keyIdentifier

        var loaded = X509CertificateInMemoryLoader.TryLoad(bytes, out var certificate);
        using (certificate)
        {
            Assert.Multiple(() =>
            {
                Assert.That(loaded, Is.True);
                Assert.That(certificate, Is.Not.Null);
            });
        }
    }

    [Test]
    public void TryLoad_ReturnsCertificate_WhenAllTypedExtensionsAreWellFormed()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=WebAuthn.Net Well-Formed Extensions", key, HashAlgorithmName.SHA256);
        var subjectKeyIdentifier = new X509SubjectKeyIdentifierExtension(request.PublicKey, false);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.2") }, false));
        request.CertificateExtensions.Add(subjectKeyIdentifier);
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(subjectKeyIdentifier));
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("example.com");
        request.CertificateExtensions.Add(sanBuilder.Build());
        using var certificate = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));

        var loaded = X509CertificateInMemoryLoader.TryLoad(certificate.RawData, out var loadedCertificate);
        using (loadedCertificate)
        {
            Assert.Multiple(() =>
            {
                Assert.That(loaded, Is.True);
                Assert.That(loadedCertificate, Is.Not.Null);
            });
        }
    }

    private static byte[] BuildCertificate(byte[]? validity, params (string Oid, bool Critical, byte[] Value)[] extensions)
    {
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var subjectKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return TpmAttestationBuilder.BuildCertificate(
            issuerKey,
            new X500DistinguishedName("CN=Issuer").RawData,
            2,
            EmptyName,
            subjectKey.ExportSubjectPublicKeyInfo(),
            TpmAttestationBuilder.Now.AddDays(-1),
            TpmAttestationBuilder.Now.AddDays(1),
            extensions,
            validity);
    }

    // Validity ::= SEQUENCE { notBefore UTCTime, notAfter UTCTime }, with the UTCTime content written verbatim
    private static byte[] Validity(string notBefore, string notAfter)
    {
        var notBeforeBytes = System.Text.Encoding.ASCII.GetBytes(notBefore);
        var notAfterBytes = System.Text.Encoding.ASCII.GetBytes(notAfter);
        var content = new byte[2 + notBeforeBytes.Length + 2 + notAfterBytes.Length];
        content[0] = 0x17;
        content[1] = (byte) notBeforeBytes.Length;
        notBeforeBytes.CopyTo(content, 2);
        content[2 + notBeforeBytes.Length] = 0x17;
        content[3 + notBeforeBytes.Length] = (byte) notAfterBytes.Length;
        notAfterBytes.CopyTo(content, 4 + notBeforeBytes.Length);
        var result = new byte[2 + content.Length];
        result[0] = 0x30;
        result[1] = (byte) content.Length;
        content.CopyTo(result, 2);
        return result;
    }
}
