using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;

namespace WebAuthn.Net.Services.Static;

public class X509CertificateInMemoryLoaderTests
{
    private static readonly byte[] EmptyName = { 0x30, 0x00 };

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

    private static byte[] BuildCertificate(byte[]? validity)
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
            Array.Empty<(string, bool, byte[])>(),
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
