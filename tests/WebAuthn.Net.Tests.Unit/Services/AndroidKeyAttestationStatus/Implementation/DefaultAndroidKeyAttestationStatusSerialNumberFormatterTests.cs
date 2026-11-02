using System;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusSerialNumberFormatter;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation;

public class DefaultAndroidKeyAttestationStatusSerialNumberFormatterTests
{
    private DefaultAndroidKeyAttestationStatusSerialNumberFormatter Formatter { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        Formatter = new();
    }

    // ---------------------------------------------------------------------------------------------
    // The serial number of a certificate

    // The keys of the status list are what BigInteger.toString(16) returns in Java: lowercase hexadecimal without leading zeros.
    [TestCase("01", "1")]
    [TestCase("00", "0")]
    // a positive serial number whose first octet has the high bit set starts with a zero octet
    [TestCase("0095424d3dbd29ca3a25bdcac5ee51187c", "95424d3dbd29ca3a25bdcac5ee51187c")]
    // the factory-provisioned attestation certificates have serial numbers whose hexadecimal digits are all decimal, like these from a Pixel 3 (the status list has such keys too)
    [TestCase("17102468407102977850", "17102468407102977850")]
    [TestCase("05014131950868983053", "5014131950868983053")]
    // longer than 128 bits, like the serial numbers of some certificate authorities in Android attestation chains (RFC 5280 allows up to 20 octets)
    [TestCase("6e8ed06f5dc8d512ed34e811cce85cae4b4c42", "6e8ed06f5dc8d512ed34e811cce85cae4b4c42")]
    public void TryFormat_ReturnsLowercaseHexadecimalWithoutLeadingZeros(string serialNumberOctets, string expected)
    {
        using var certificate = CreateCertificate(Convert.FromHexString(serialNumberOctets));

        var formatted = Formatter.TryFormat(certificate, out var serialNumber);

        Assert.Multiple(() =>
        {
            Assert.That(Convert.ToHexStringLower(certificate.SerialNumberBytes.Span), Is.EqualTo(serialNumberOctets));
            Assert.That(formatted, Is.True);
            Assert.That(serialNumber, Is.EqualTo(expected));
        });
    }

    [TestCase("80")]
    [TestCase("ff01")]
    public void TryFormat_ReturnsFalse_WhenSerialNumberIsNegative(string serialNumberOctets)
    {
        // a non-conforming certificate authority may issue a certificate with a negative serial number, and the status list has no such keys
        using var certificate = CreateCertificate(Convert.FromHexString(serialNumberOctets));

        var formatted = Formatter.TryFormat(certificate, out var serialNumber);

        Assert.Multiple(() =>
        {
            Assert.That(Convert.ToHexStringLower(certificate.SerialNumberBytes.Span), Is.EqualTo(serialNumberOctets));
            Assert.That(formatted, Is.False);
            Assert.That(serialNumber, Is.Null);
        });
    }

    // ---------------------------------------------------------------------------------------------
    // The keys of the status list

    [TestCase("1", "1")]
    [TestCase("95424d3dbd29ca3a25bdcac5ee51187c", "95424d3dbd29ca3a25bdcac5ee51187c")]
    [TestCase("6681152659205225093", "6681152659205225093")]
    [TestCase("1A2B", "1a2b")]
    [TestCase("001a2b", "1a2b")]
    [TestCase("0", "0")]
    [TestCase("000", "0")]
    public void TryNormalize_ReturnsLowercaseHexadecimalWithoutLeadingZeros(string key, string expected)
    {
        var normalized = Formatter.TryNormalize(key, out var serialNumber);

        Assert.Multiple(() =>
        {
            Assert.That(normalized, Is.True);
            Assert.That(serialNumber, Is.EqualTo(expected));
        });
    }

    [TestCase("")]
    [TestCase("xyz")]
    [TestCase("-1a")]
    [TestCase(" 1a")]
    [TestCase("1a ")]
    [TestCase("0x1a")]
    // decimal digits of other scripts (Arabic-Indic and fullwidth)
    [TestCase("١٢")]
    [TestCase("１２")]
    public void TryNormalize_ReturnsFalse_WhenKeyIsNotSerialNumberInHexadecimal(string key)
    {
        var normalized = Formatter.TryNormalize(key, out var serialNumber);

        Assert.Multiple(() =>
        {
            Assert.That(normalized, Is.False);
            Assert.That(serialNumber, Is.Null);
        });
    }

    // A self-signed certificate whose serial number has exactly the given content octets: CertificateRequest would make a negative serial number positive.
    private static X509Certificate2 CreateCertificate(byte[] serialNumberOctets)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signatureGenerator = X509SignatureGenerator.CreateForECDsa(key);
        var signatureAlgorithm = signatureGenerator.GetSignatureAlgorithmIdentifier(HashAlgorithmName.SHA256);
        var name = new X500DistinguishedName("CN=WebAuthn.Net Android Key Status Test");
        var now = DateTimeOffset.UtcNow;
        var tbsCertificate = new AsnWriter(AsnEncodingRules.DER);
        using (tbsCertificate.PushSequence())
        {
            using (tbsCertificate.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                tbsCertificate.WriteInteger(2);
            }

            tbsCertificate.WriteEncodedValue([0x02, (byte) serialNumberOctets.Length, ..serialNumberOctets]);
            tbsCertificate.WriteEncodedValue(signatureAlgorithm);
            tbsCertificate.WriteEncodedValue(name.RawData);
            using (tbsCertificate.PushSequence())
            {
                tbsCertificate.WriteUtcTime(now.AddDays(-1));
                tbsCertificate.WriteUtcTime(now.AddDays(1));
            }

            tbsCertificate.WriteEncodedValue(name.RawData);
            tbsCertificate.WriteEncodedValue(key.ExportSubjectPublicKeyInfo());
        }

        var tbsCertificateOctets = tbsCertificate.Encode();
        var certificate = new AsnWriter(AsnEncodingRules.DER);
        using (certificate.PushSequence())
        {
            certificate.WriteEncodedValue(tbsCertificateOctets);
            certificate.WriteEncodedValue(signatureAlgorithm);
            certificate.WriteBitString(signatureGenerator.SignData(tbsCertificateOctets, HashAlgorithmName.SHA256));
        }

        return X509CertificateLoader.LoadCertificate(certificate.Encode());
    }
}
