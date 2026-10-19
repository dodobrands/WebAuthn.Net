using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;

namespace WebAuthn.Net.Services.Static;

public class X509TrustChainValidatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Test]
    public void IsFidoMetadataBlobJwtChainValid_ReturnsTrue_WhenChainEndsInRoot()
    {
        using var root = CreateRoot("CN=WebAuthn.Net Test Metadata Root");
        using var leaf = CreateLeaf(root);

        var valid = X509TrustChainValidator.IsFidoMetadataBlobJwtChainValid(new[] { root }, new[] { leaf }, ConfigureChain);
        var validWithStatus = X509TrustChainValidator.IsFidoMetadataBlobJwtChainValid(new[] { root }, new[] { leaf }, ConfigureChain, out var chainStatus);

        Assert.Multiple(() =>
        {
            Assert.That(valid, Is.True);
            Assert.That(validWithStatus, Is.True);
            Assert.That(chainStatus, Is.Empty);
        });
    }

    [Test]
    public void IsFidoMetadataBlobJwtChainValid_ReturnsFalse_WithChainStatus_WhenChainEndsInAnotherRoot()
    {
        using var root = CreateRoot("CN=WebAuthn.Net Test Metadata Root");
        using var leaf = CreateLeaf(root);
        using var otherRoot = CreateRoot("CN=WebAuthn.Net Other Root");

        var valid = X509TrustChainValidator.IsFidoMetadataBlobJwtChainValid(new[] { otherRoot }, new[] { leaf }, ConfigureChain, out var chainStatus);

        Assert.Multiple(() =>
        {
            Assert.That(valid, Is.False);
            Assert.That(chainStatus, Is.Not.Empty);
        });
    }

    [Test]
    public void IsFidoMetadataBlobJwtChainValid_ReturnsFalse_WhenThereAreNoRoots()
    {
        using var root = CreateRoot("CN=WebAuthn.Net Test Metadata Root");
        using var leaf = CreateLeaf(root);

        var valid = X509TrustChainValidator.IsFidoMetadataBlobJwtChainValid(Array.Empty<X509Certificate2>(), new[] { leaf }, ConfigureChain, out var chainStatus);

        Assert.Multiple(() =>
        {
            Assert.That(valid, Is.False);
            Assert.That(chainStatus, Is.Empty);
        });
    }

    private static void ConfigureChain(X509Chain chain)
    {
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = Now.UtcDateTime;
    }

    // a self-signed CA certificate together with its private key
    private static X509Certificate2 CreateRoot(string subject)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return request.CreateSelfSigned(Now.AddYears(-1), Now.AddYears(1));
    }

    private static X509Certificate2 CreateLeaf(X509Certificate2 root)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=WebAuthn.Net Test Metadata Signer", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        return request.Create(root, Now.AddDays(-1), Now.AddDays(30), new byte[] { 1, 2, 3, 4 });
    }
}
