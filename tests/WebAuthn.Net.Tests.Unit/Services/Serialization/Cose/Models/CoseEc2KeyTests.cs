using System;
using System.Security.Cryptography;
using NUnit.Framework;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;

namespace WebAuthn.Net.Services.Serialization.Cose.Models;

public class CoseEc2KeyTests
{
    [Test]
    public void Matches_X509Certificate2_ReturnsTrue_WhenCertificateHasTheSameKey()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificate = CoseKeyTestMaterial.SelfSigned(key);
        var coseKey = CoseKeyTestMaterial.ToCoseEc2Key(key);

        Assert.That(coseKey.Matches(certificate), Is.True);
    }

    [Test]
    public void Matches_X509Certificate2_ReturnsFalse_WhenCertificateHasAnotherKey()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificate = CoseKeyTestMaterial.SelfSigned(certificateKey);
        var coseKey = CoseKeyTestMaterial.ToCoseEc2Key(key);

        Assert.That(coseKey.Matches(certificate), Is.False);
    }

    [Test]
    public void Matches_X509Certificate2_ReturnsFalse_WithoutException_WhenCertificateKeyHasExplicitCurveParametersOfAnUnnamedCurve()
    {
        // the platform cannot map the parameters to a named curve, so the exported ECCurve has no Oid
        using var certificate = CoseKeyTestMaterial.LoadOrIgnore(CoseKeyTestMaterial.ExplicitCurveP256NegatedGeneratorSubjectPublicKeyInfo());
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var coseKey = CoseKeyTestMaterial.ToCoseEc2Key(key);

        var matches = true;
        Assert.DoesNotThrow(() => matches = coseKey.Matches(certificate));
        Assert.That(matches, Is.False);
    }

    [Test]
    public void Matches_X509Certificate2_ReturnsFalse_WithoutException_WhenCertificateKeyHasExplicitCurveParameters()
    {
        using var certificate = CoseKeyTestMaterial.LoadOrIgnore(TpmAttestationBuilder.ExplicitCurveP256SubjectPublicKeyInfo());
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var coseKey = CoseKeyTestMaterial.ToCoseEc2Key(key);

        var matches = true;
        Assert.DoesNotThrow(() => matches = coseKey.Matches(certificate));
        Assert.That(matches, Is.False);
    }

    [Test]
    public void Matches_X509Certificate2_ReturnsFalse_WithoutException_WhenCertificateKeyIsNotOnTheCurve()
    {
        using var certificate = CoseKeyTestMaterial.LoadOrIgnore(TpmAttestationBuilder.OffCurveP256SubjectPublicKeyInfo());
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var coseKey = CoseKeyTestMaterial.ToCoseEc2Key(key);

        var matches = true;
        Assert.DoesNotThrow(() => matches = coseKey.Matches(certificate));
        Assert.That(matches, Is.False);
    }

    [Test]
    public void Matches_AsymmetricAlgorithm_ReturnsTrue_WhenKeyIsTheSame()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var coseKey = CoseKeyTestMaterial.ToCoseEc2Key(key);

        Assert.That(coseKey.Matches((AsymmetricAlgorithm) key), Is.True);
    }

    [Test]
    public void Matches_AsymmetricAlgorithm_ReturnsFalse_WhenKeyIsAnother()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var coseKey = CoseKeyTestMaterial.ToCoseEc2Key(key);

        Assert.That(coseKey.Matches((AsymmetricAlgorithm) otherKey), Is.False);
    }

    [Test]
    public void Matches_AsymmetricAlgorithm_ReturnsFalse_WhenAlgorithmIsNotEcdsa()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var rsa = RSA.Create(2048);
        var coseKey = CoseKeyTestMaterial.ToCoseEc2Key(key);

        Assert.That(coseKey.Matches((AsymmetricAlgorithm) rsa), Is.False);
    }

    [Test]
    public void Matches_AsymmetricAlgorithm_ReturnsFalse_WithoutException_WhenKeyHasExplicitCurveParameters()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var coseKey = CoseKeyTestMaterial.ToCoseEc2Key(key);
        // the same point, but on a curve given by explicit parameters (ECCurve.Oid is null), as a platform exports a key whose parameters it could not map to a named curve
        using var explicitCurveKey = new ExplicitCurveECDsa(new()
        {
            Curve = CoseKeyTestMaterial.ExplicitP256Curve(),
            Q = key.ExportParameters(false).Q
        });

        var matches = true;
        Assert.DoesNotThrow(() => matches = coseKey.Matches((AsymmetricAlgorithm) explicitCurveKey));
        Assert.That(matches, Is.False);
    }

    [Test]
    public void Matches_AsymmetricAlgorithm_ReturnsFalse_WithoutException_WhenExportParametersThrowsCryptographicException()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var coseKey = CoseKeyTestMaterial.ToCoseEc2Key(key);
        using var unusableKey = new UnexportableECDsa();

        var matches = true;
        Assert.DoesNotThrow(() => matches = coseKey.Matches((AsymmetricAlgorithm) unusableKey));
        Assert.That(matches, Is.False);
    }

    // an ECDsa that exports the given parameters
    private sealed class ExplicitCurveECDsa : ECDsa
    {
        private readonly ECParameters _parameters;

        public ExplicitCurveECDsa(ECParameters parameters)
        {
            _parameters = parameters;
        }

        public override ECParameters ExportParameters(bool includePrivateParameters)
        {
            return _parameters;
        }

        public override byte[] SignHash(byte[] hash)
        {
            throw new NotSupportedException();
        }

        public override bool VerifyHash(byte[] hash, byte[] signature)
        {
            throw new NotSupportedException();
        }
    }

    // an ECDsa whose public key the platform cannot export
    private sealed class UnexportableECDsa : ECDsa
    {
        public override ECParameters ExportParameters(bool includePrivateParameters)
        {
            throw new CryptographicException("The key cannot be exported");
        }

        public override byte[] SignHash(byte[] hash)
        {
            throw new NotSupportedException();
        }

        public override bool VerifyHash(byte[] hash, byte[] signature)
        {
            throw new NotSupportedException();
        }
    }
}
