using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation;

public class AndroidKeyAttestationStatusListTests
{
    // The serial numbers of the status list are what BigInteger.toString(16) returns in Java: lowercase hexadecimal without leading zeros.
    [TestCase("01", "1")]
    [TestCase("000001", "1")]
    [TestCase("00", "0")]
    // a DER INTEGER whose first octet has the high bit set starts with a zero octet
    [TestCase("00ab", "ab")]
    [TestCase("0095424d3dbd29ca3a25bdcac5ee51187c", "95424d3dbd29ca3a25bdcac5ee51187c")]
    // the factory-provisioned attestation certificates have serial numbers whose hexadecimal digits are all decimal, like these from a Pixel 3 (the status list has such keys too)
    [TestCase("17102468407102977850", "17102468407102977850")]
    [TestCase("05014131950868983053", "5014131950868983053")]
    public void FormatSerialNumber_ReturnsLowercaseHexadecimalWithoutLeadingZeros(string serialNumberHex, string expected)
    {
        var result = AndroidKeyAttestationStatusList.FormatSerialNumber(Convert.FromHexString(serialNumberHex));

        Assert.That(result, Is.EqualTo(expected));
    }

    [TestCase("")]
    [TestCase("80")]
    [TestCase("ff01")]
    public void FormatSerialNumber_ReturnsNull_WhenSerialNumberIsEmptyOrNegative(string serialNumberHex)
    {
        var result = AndroidKeyAttestationStatusList.FormatSerialNumber(Convert.FromHexString(serialNumberHex));

        Assert.That(result, Is.Null);
    }

    [Test]
    public void TryFindEntry_FindsCertificate_BySerialNumberWithoutLeadingZeroOctet()
    {
        using var certificate = CreateCertificate(Convert.FromHexString("95424d3dbd29ca3a25bdcac5ee51187c"));
        var statusList = new AndroidKeyAttestationStatusList(new Dictionary<string, AndroidKeyAttestationStatusEntry>
        {
            ["95424d3dbd29ca3a25bdcac5ee51187c"] = new("REVOKED", "KEY_COMPROMISE")
        });

        var found = statusList.TryFindEntry(certificate, out var serialNumber, out var entry);

        Assert.Multiple(() =>
        {
            // the certificate encodes the serial number with a leading zero octet, because the high bit of its first octet is set
            Assert.That(Convert.ToHexStringLower(certificate.SerialNumberBytes.Span), Is.EqualTo("0095424d3dbd29ca3a25bdcac5ee51187c"));
            Assert.That(found, Is.True);
            Assert.That(serialNumber, Is.EqualTo("95424d3dbd29ca3a25bdcac5ee51187c"));
            Assert.That(entry?.Status, Is.EqualTo("REVOKED"));
            Assert.That(entry?.Reason, Is.EqualTo("KEY_COMPROMISE"));
        });
    }

    [Test]
    public void TryFindEntry_ReturnsFalse_WhenCertificateIsNotInStatusList()
    {
        using var certificate = CreateCertificate(Convert.FromHexString("17102468407102977850"));
        var statusList = new AndroidKeyAttestationStatusList(new Dictionary<string, AndroidKeyAttestationStatusEntry>
        {
            // neither the serial number in decimal nor another serial number names the certificate
            [new BigInteger(Convert.FromHexString("17102468407102977850"), true, true).ToString(CultureInfo.InvariantCulture)] = new("REVOKED", null),
            ["1710246840710297785"] = new("REVOKED", null)
        });

        var found = statusList.TryFindEntry(certificate, out var serialNumber, out var entry);

        Assert.Multiple(() =>
        {
            Assert.That(found, Is.False);
            Assert.That(serialNumber, Is.Null);
            Assert.That(entry, Is.Null);
        });
    }

    private static X509Certificate2 CreateCertificate(byte[] serialNumber)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=WebAuthn.Net Android Key Status Test", key, HashAlgorithmName.SHA256);
        var now = DateTimeOffset.UtcNow;
        return request.Create(request.SubjectName, X509SignatureGenerator.CreateForECDsa(key), now.AddDays(-1), now.AddDays(1), serialNumber);
    }
}
