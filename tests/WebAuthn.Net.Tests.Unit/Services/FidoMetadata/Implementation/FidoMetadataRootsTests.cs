using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider.Constants;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

// The root certificate of the FIDO Metadata Service embedded in the library is GlobalSign Root R46, the only root certificate that FIDO publishes for verifying the blob
// (https://fidoalliance.org/metadata/, the root signing trust anchor of FIDO Metadata Service v3.1.1 §3.2). The genuine blob (no: 291) chains up to it,
// see DefaultFidoMetadataProviderTests and DefaultFidoMetadataProviderEmbeddedBlobTests.
public class FidoMetadataRootsTests
{
    // SHA-256 of GlobalSign Root R46 (C=BE, O=GlobalSign nv-sa, CN=GlobalSign Root R46), valid until 2046-03-20
    private const string GlobalSignRootR46Sha256 = "4FA3126D8D3A11D1C4855A4F807CBAD6CF919D3A5A88B03BEA2C6372D93C40C9";

    // The certificate that signed the genuine blob (no: 98) published in 2024: it is issued to mds.fidoalliance.org for TLS server authentication (like the current signing certificate)
    // and was valid from 2024-06-26 to 2025-07-28. Its issuer, GlobalSign Extended Validation CA - SHA256 - G3, is issued by GlobalSign Root CA - R3.
    private const string EarlierSigningCertificate =
        "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";

    private const string EarlierSigningCertificateIssuer =
        "MIIEYTCCA0mgAwIBAgIOSKQC3SeSDaIINJ3RmXswDQYJKoZIhvcNAQELBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTYwOTIxMDAwMDAwWhcNMjYwOTIxMDAwMDAwWjBiMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTE4MDYGA1UEAxMvR2xvYmFsU2lnbiBFeHRlbmRlZCBWYWxpZGF0aW9uIENBIC0gU0hBMjU2IC0gRzMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrawNnVNXcEfvFohPBjBkn3BB04mGDPfqO24+lD+SpvkY/Ar5EpAkcJjOfR0iBFYhWN80HzpXYy2tIA7mbXpKu2JpmYdU1xcoQpQK0ujE/we+vEDyjyjmtf76LLqbOfuq3xZbSqUqAY+MOvA67nnpdawvkHgJBFVPnxui45XH4BwTwbtDucx+Mo7EK4mS0Ti+P1NzARxFNCUFM8Wxc32wxXKff6WU4TbqUx/UJm485ttkFqu0Ox4wTUUbn0uuzK7yV3Y986EtGzhKBraMH36MekSYlE473GqHetRi9qbNG5pM++Sa+WjR9E1e0Yws16CGqsmVKwAqg4uc43eBTFUhVAgMBAAGjggEpMIIBJTAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU3bPnbagu6MVObs905nU8lBXO6B0wHwYDVR0jBBgwFoAUj/BLf6guRSSuTVD6Y5qL3uLdG7wwPgYIKwYBBQUHAQEEMjAwMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHIzMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vcm9vdC1yMy5jcmwwRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQBVaJzl0J/i0zUV38iMXIQ+Q/yht+JZZ5DW1otGL5OYV0LZ6ZE6xh+WuvWJJ4hrDbhfo6khUEaFtRUnurqzutvVyWgW8msnoP0gtMZO11cwPUMUuUV8iGyIOuIB0flo6G+XbV74SZuR5v5RAgqgGXucYUPZWvv9AfzMMQhRQkr/MO/WR2XSdiBrXHoDL2xk4DmjA4K6iPI+1+qMhyrkUM/2ZEdA8ldqwl8nQDkKS7vq6sUZ5LPVdfpxJZZu5JBj4y7FNFTVW1OMlCUvwt5H8aFgBMLFik9xqK6JFHpYxYmf4t2sLLxN0LlCthJEabvp10ZlOtfu8hL5gCXcxnwGxzSb";

    // GlobalSign Root CA - R3, valid until 2029-03-18
    private const string GlobalSignRootR3 =
        "MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsTgHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmmKPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zdQQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZXriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+oLkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZURUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMpjjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQXmcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecsMx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpHWD9f";

    [Test]
    public void GlobalSign_ContainsOnlyGlobalSignRootR46()
    {
        var fingerprints = FidoMetadataRoots.GlobalSign.Select(static x => Convert.ToHexString(SHA256.HashData(x))).ToArray();

        Assert.That(fingerprints, Is.EqualTo(new[] { GlobalSignRootR46Sha256 }));
    }

    [Test]
    public void GlobalSign_DoesNotValidateChainOfEarlierSigningCertificate_ThatEndsInGlobalSignRootR3()
    {
        // The chain is validated with the default policy of the embedded blob, which ignores the validity period of the certificates and doesn't use the network.
        // So the chain is rejected only because GlobalSign Root CA - R3 is not a trust anchor: with it, the same chain is valid.
        using var signingCertificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(EarlierSigningCertificate));
        using var issuer = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(EarlierSigningCertificateIssuer));
        using var globalSignRootR3 = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(GlobalSignRootR3));
        var roots = FidoMetadataRoots.GlobalSign.Select(static x => X509CertificateLoader.LoadCertificate(x)).ToArray();
        try
        {
            var trustPath = new[] { signingCertificate, issuer };
            var policy = new X509ChainValidationOptions().OnValidateEmbeddedFidoMetadataBlobJwtChain;

            var valid = X509TrustChainValidator.IsFidoMetadataBlobJwtChainValid(roots, trustPath, policy, out var chainStatus);
            var validWithGlobalSignRootR3 = X509TrustChainValidator.IsFidoMetadataBlobJwtChainValid(new[] { globalSignRootR3 }, trustPath, policy);

            Assert.Multiple(() =>
            {
                Assert.That(valid, Is.False);
                Assert.That(chainStatus, Is.Not.Empty);
                Assert.That(validWithGlobalSignRootR3, Is.True);
            });
        }
        finally
        {
            foreach (var root in roots)
            {
                root.Dispose();
            }
        }
    }
}
