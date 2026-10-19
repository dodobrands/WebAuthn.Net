using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;
using WebAuthn.Net.Services.Serialization.Cose.Models;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2;

namespace WebAuthn.Net.Services.Cryptography.Sign.Implementation;

public class DefaultDigitalSignatureVerifierTests
{
    private static readonly byte[] Data = { 0x01, 0x02, 0x03 };

    // a syntactically valid ECDSA-Sig-Value: SEQUENCE { INTEGER 1, INTEGER 1 }
    private static readonly byte[] Signature = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 };

    [Test]
    public void IsValidCertificateSign_ReturnsTrue_WhenSignatureIsValid()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Signer", key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(TpmAttestationBuilder.Now.AddDays(-1), TpmAttestationBuilder.Now.AddDays(1));
        var signature = key.SignData(Data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var valid = new DefaultDigitalSignatureVerifier().IsValidCertificateSign(certificate, CoseAlgorithm.ES256, Data, signature);

        Assert.That(valid, Is.True);
    }

    [Test]
    public void IsValidCertificateSign_ReturnsFalse_WithoutException_WhenPublicKeyIsNotOnTheCurve()
    {
        using var certificate = LoadOrIgnore(TpmAttestationBuilder.OffCurveP256SubjectPublicKeyInfo());

        var valid = true;
        Assert.DoesNotThrow(() => valid = new DefaultDigitalSignatureVerifier().IsValidCertificateSign(certificate, CoseAlgorithm.ES256, Data, Signature));
        Assert.That(valid, Is.False);
    }

    [Test]
    public void IsValidCertificateSign_ReturnsFalse_WithoutException_WhenPublicKeyHasExplicitCurveParameters()
    {
        using var certificate = LoadOrIgnore(TpmAttestationBuilder.ExplicitCurveP256SubjectPublicKeyInfo());

        var valid = true;
        Assert.DoesNotThrow(() => valid = new DefaultDigitalSignatureVerifier().IsValidCertificateSign(certificate, CoseAlgorithm.ES256, Data, Signature));
        Assert.That(valid, Is.False);
    }

    [Test]
    public void IsValidCoseKeySign_ReturnsFalse_WithoutException_WhenPublicKeyIsNotOnTheCurve()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var point = key.ExportParameters(false).Q;
        var y = point.Y!.AsSpan().ToArray();
        y[^1] ^= 0x01;
        var coseKey = new CoseEc2Key(CoseAlgorithm.ES256, CoseEc2EllipticCurve.P256, point.X!, y);

        var valid = true;
        Assert.DoesNotThrow(() => valid = new DefaultDigitalSignatureVerifier().IsValidCoseKeySign(coseKey, Data, Signature));
        Assert.That(valid, Is.False);
    }

    // a certificate whose subject public key is the given SubjectPublicKeyInfo; some platforms refuse to load it at all, which is not what these tests are about
    private static X509Certificate2 LoadOrIgnore(byte[] subjectPublicKeyInfo)
    {
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var bytes = TpmAttestationBuilder.BuildCertificate(
            issuerKey,
            new X500DistinguishedName("CN=Issuer").RawData,
            2,
            new X500DistinguishedName("CN=Subject").RawData,
            subjectPublicKeyInfo,
            TpmAttestationBuilder.Now.AddDays(-1),
            TpmAttestationBuilder.Now.AddDays(1),
            Array.Empty<(string, bool, byte[])>());
        try
        {
#if NET8_0
            return new(bytes);
#else
            return X509CertificateLoader.LoadCertificate(bytes);
#endif
        }
        catch (CryptographicException exception)
        {
            Assert.Ignore($"The platform does not load this certificate: {exception.Message}");
            throw;
        }
    }
}
