using System.Security.Cryptography;
using NUnit.Framework;

namespace WebAuthn.Net.Services.Serialization.Cose.Models;

public class CoseRsaKeyTests
{
    [Test]
    public void Matches_X509Certificate2_ReturnsTrue_WhenCertificateHasTheSameKey()
    {
        using var key = RSA.Create(2048);
        using var certificate = CoseKeyTestMaterial.SelfSigned(key);
        var coseKey = CoseKeyTestMaterial.ToCoseRsaKey(key);

        Assert.That(coseKey.Matches(certificate), Is.True);
    }

    [Test]
    public void Matches_X509Certificate2_ReturnsFalse_WhenCertificateHasAnotherKey()
    {
        using var key = RSA.Create(2048);
        using var certificateKey = RSA.Create(2048);
        using var certificate = CoseKeyTestMaterial.SelfSigned(certificateKey);
        var coseKey = CoseKeyTestMaterial.ToCoseRsaKey(key);

        Assert.That(coseKey.Matches(certificate), Is.False);
    }

    [Test]
    public void Matches_X509Certificate2_ReturnsFalse_WithoutException_WhenCertificateKeyIsMalformed()
    {
        // the certificate loads, but its rsaEncryption key is not an RSAPublicKey structure, so extracting it throws CryptographicException
        using var certificate = CoseKeyTestMaterial.LoadOrIgnore(CoseKeyTestMaterial.MalformedRsaSubjectPublicKeyInfo());
        CoseKeyTestMaterial.IgnoreUnlessRsaPublicKeyExtractionFailsWithCryptographicException(certificate);
        using var key = RSA.Create(2048);
        var coseKey = CoseKeyTestMaterial.ToCoseRsaKey(key);

        var matches = true;
        Assert.DoesNotThrow(() => matches = coseKey.Matches(certificate));
        Assert.That(matches, Is.False);
    }

    [Test]
    public void Matches_AsymmetricAlgorithm_ReturnsTrue_WhenKeyIsTheSame()
    {
        using var key = RSA.Create(2048);
        var coseKey = CoseKeyTestMaterial.ToCoseRsaKey(key);

        Assert.That(coseKey.Matches((AsymmetricAlgorithm) key), Is.True);
    }

    [Test]
    public void Matches_AsymmetricAlgorithm_ReturnsFalse_WhenKeyIsAnother()
    {
        using var key = RSA.Create(2048);
        using var otherKey = RSA.Create(2048);
        var coseKey = CoseKeyTestMaterial.ToCoseRsaKey(key);

        Assert.That(coseKey.Matches((AsymmetricAlgorithm) otherKey), Is.False);
    }

    [Test]
    public void Matches_AsymmetricAlgorithm_ReturnsFalse_WhenAlgorithmIsNotRsa()
    {
        using var key = RSA.Create(2048);
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var coseKey = CoseKeyTestMaterial.ToCoseRsaKey(key);

        Assert.That(coseKey.Matches((AsymmetricAlgorithm) ecdsa), Is.False);
    }

    [Test]
    public void Matches_AsymmetricAlgorithm_ReturnsFalse_WithoutException_WhenExportParametersThrowsCryptographicException()
    {
        using var key = RSA.Create(2048);
        var coseKey = CoseKeyTestMaterial.ToCoseRsaKey(key);
        using var unusableKey = new UnexportableRSA();

        var matches = true;
        Assert.DoesNotThrow(() => matches = coseKey.Matches((AsymmetricAlgorithm) unusableKey));
        Assert.That(matches, Is.False);
    }

    // an RSA whose public key the platform cannot export
    private sealed class UnexportableRSA : RSA
    {
        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            throw new CryptographicException("The key cannot be exported");
        }

        public override void ImportParameters(RSAParameters parameters)
        {
            throw new CryptographicException("The key cannot be imported");
        }
    }
}
