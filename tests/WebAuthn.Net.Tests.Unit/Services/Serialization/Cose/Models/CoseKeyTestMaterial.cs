using System;
using System.Formats.Asn1;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2;

namespace WebAuthn.Net.Services.Serialization.Cose.Models;

// keys and certificates that CertificateRequest and ECDsa.Create cannot produce, for the tests of AbstractCoseKey.Matches and of the digital signature verifier
public static class CoseKeyTestMaterial
{
    // NIST P-256 domain parameters (SEC 2, secp256r1)
    private const string P256Prime = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
    private const string P256A = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC";
    private const string P256B = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";
    private const string P256Gx = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
    private const string P256Gy = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";
    private const string P256Order = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";

    // the P-256 parameters in their explicit form: CurveType is PrimeShortWeierstrass and Oid is null - what a platform exports for a key whose parameters it could not map to a named curve
    public static ECCurve ExplicitP256Curve()
    {
        return new()
        {
            CurveType = ECCurve.ECCurveType.PrimeShortWeierstrass,
            Prime = Convert.FromHexString(P256Prime),
            A = Convert.FromHexString(P256A),
            B = Convert.FromHexString(P256B),
            G = new()
            {
                X = Convert.FromHexString(P256Gx),
                Y = Convert.FromHexString(P256Gy)
            },
            Order = Convert.FromHexString(P256Order),
            Cofactor = new byte[] { 0x01 }
        };
    }

    // SubjectPublicKeyInfo of a P-256 key with explicit curve parameters (SpecifiedECDomain, RFC 3279 §2.3.5) whose generator is -G:
    // a valid generator of the same group that no named curve has, so a platform that maps explicit parameters back to a named curve when they are byte-identical (OpenSSL) cannot do so here
    public static byte[] ExplicitCurveP256NegatedGeneratorSubjectPublicKeyInfo()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = key.ExportParameters(false);
        var prime = new BigInteger(Convert.FromHexString(P256Prime), true, true);
        var generatorY = new BigInteger(Convert.FromHexString(P256Gy), true, true);
        var negatedGeneratorY = (prime - generatorY).ToByteArray(true, true);
        var paddedNegatedGeneratorY = new byte[32];
        negatedGeneratorY.CopyTo(paddedNegatedGeneratorY, 32 - negatedGeneratorY.Length);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.2.840.10045.2.1"); // id-ecPublicKey
                using (writer.PushSequence())
                {
                    writer.WriteInteger(1);
                    using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier("1.2.840.10045.1.1"); // prime-field
                        writer.WriteIntegerUnsigned(Convert.FromHexString(P256Prime));
                    }

                    using (writer.PushSequence())
                    {
                        writer.WriteOctetString(Convert.FromHexString(P256A));
                        writer.WriteOctetString(Convert.FromHexString(P256B));
                    }

                    writer.WriteOctetString(new byte[] { 0x04 }.Concat(Convert.FromHexString(P256Gx)).Concat(paddedNegatedGeneratorY).ToArray());
                    writer.WriteIntegerUnsigned(Convert.FromHexString(P256Order));
                    writer.WriteIntegerUnsigned(new byte[] { 0x01 });
                }
            }

            writer.WriteBitString(new byte[] { 0x04 }.Concat(parameters.Q.X!).Concat(parameters.Q.Y!).ToArray());
        }

        return writer.Encode();
    }

    // SubjectPublicKeyInfo with the rsaEncryption algorithm whose subjectPublicKey is not an RSAPublicKey structure
    public static byte[] MalformedRsaSubjectPublicKeyInfo()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier("1.2.840.113549.1.1.1"); // rsaEncryption
                writer.WriteNull();
            }

            writer.WriteBitString(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 });
        }

        return writer.Encode();
    }

    // a certificate whose subject public key is the given SubjectPublicKeyInfo; some platforms refuse to load it at all, which is not what the tests using it are about
    public static X509Certificate2 LoadOrIgnore(byte[] subjectPublicKeyInfo)
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
            return X509CertificateLoader.LoadCertificate(bytes);
        }
        catch (CryptographicException exception)
        {
            Assert.Ignore($"The platform does not load this certificate: {exception.Message}");
            throw;
        }
    }

    // a platform may report an unusable RSA key with an exception other than CryptographicException (macOS: ArgumentException for an invalid SecKey handle);
    // X509CertificateInMemoryLoader.TryLoad rejects such a certificate before it reaches the library, so a test about CryptographicException cannot use it there
    public static void IgnoreUnlessRsaPublicKeyExtractionFailsWithCryptographicException(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        try
        {
            certificate.GetRSAPublicKey()?.Dispose();
        }
        catch (CryptographicException)
        {
            // the platform reports the key the way the library expects
        }
        catch (ArgumentException exception)
        {
            Assert.Ignore($"The platform reports the malformed key with {exception.GetType().Name} instead of CryptographicException: {exception.Message}");
        }
    }

    public static X509Certificate2 SelfSigned(ECDsa key)
    {
        var request = new CertificateRequest("CN=Subject", key, HashAlgorithmName.SHA256);
        return request.CreateSelfSigned(TpmAttestationBuilder.Now.AddDays(-1), TpmAttestationBuilder.Now.AddDays(1));
    }

    public static X509Certificate2 SelfSigned(RSA key)
    {
        var request = new CertificateRequest("CN=Subject", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(TpmAttestationBuilder.Now.AddDays(-1), TpmAttestationBuilder.Now.AddDays(1));
    }

    public static CoseEc2Key ToCoseEc2Key(ECDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var point = key.ExportParameters(false).Q;
        return new(CoseAlgorithm.ES256, CoseEc2EllipticCurve.P256, point.X!, point.Y!);
    }

    public static CoseRsaKey ToCoseRsaKey(RSA key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var parameters = key.ExportParameters(false);
        return new(CoseAlgorithm.RS256, parameters.Modulus!, parameters.Exponent!);
    }
}
