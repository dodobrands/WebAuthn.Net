using System;
using System.Formats.Cbor;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;
using WebAuthn.Net.Services.Serialization.Cbor.Implementation;
using WebAuthn.Net.Services.Serialization.Cose.Models;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.OKP;

namespace WebAuthn.Net.Services.Serialization.Cose.Implementation;

public class DefaultCoseKeyDeserializerTests
{
    private static readonly byte[] PublicExponent65537 = { 0x01, 0x00, 0x01 };

    private FakeLogger<DefaultCoseKeyDeserializer> _logger = null!;
    private DefaultCoseKeyDeserializer _deserializer = null!;

    [SetUp]
    public void SetUp()
    {
        _logger = new();
        _deserializer = new(new DefaultCborDeserializer(new FakeLogger<DefaultCborDeserializer>()), _logger);
    }

    // ---------- EC2

    [TestCase(CoseAlgorithm.ES256, CoseEc2EllipticCurve.P256, 32)]
    [TestCase(CoseAlgorithm.ES384, CoseEc2EllipticCurve.P384, 48)]
    [TestCase(CoseAlgorithm.ES512, CoseEc2EllipticCurve.P521, 66)]
    public void Deserialize_ReturnsEc2Key_WhenCoordinatesHaveTheLengthOfTheFieldElement(CoseAlgorithm alg, CoseEc2EllipticCurve crv, int coordinateLength)
    {
        using var key = ECDsa.Create(ToECCurve(crv));
        var point = key.ExportParameters(false).Q;
        Assert.That(point.X, Has.Length.EqualTo(coordinateLength));
        Assert.That(point.Y, Has.Length.EqualTo(coordinateLength));

        var result = _deserializer.Deserialize(Ec2CoseKey(alg, crv, point.X!, point.Y!));

        var coseKey = Deserialized<CoseEc2Key>(result);
        Assert.That(coseKey.Alg, Is.EqualTo(alg));
        Assert.That(coseKey.Crv, Is.EqualTo(crv));
        Assert.That(coseKey.X, Is.EqualTo(point.X));
        Assert.That(coseKey.Y, Is.EqualTo(point.Y));
    }

    [TestCase(CoseAlgorithm.ES256, CoseEc2EllipticCurve.P256, 32, 31, 32)]
    [TestCase(CoseAlgorithm.ES256, CoseEc2EllipticCurve.P256, 32, 32, 31)]
    [TestCase(CoseAlgorithm.ES256, CoseEc2EllipticCurve.P256, 32, 33, 33)]
    [TestCase(CoseAlgorithm.ES256, CoseEc2EllipticCurve.P256, 32, 0, 0)]
    [TestCase(CoseAlgorithm.ES256, CoseEc2EllipticCurve.P256, 32, 48, 48)]
    [TestCase(CoseAlgorithm.ES384, CoseEc2EllipticCurve.P384, 48, 32, 32)]
    [TestCase(CoseAlgorithm.ES384, CoseEc2EllipticCurve.P384, 48, 47, 48)]
    [TestCase(CoseAlgorithm.ES512, CoseEc2EllipticCurve.P521, 66, 65, 65)]
    [TestCase(CoseAlgorithm.ES512, CoseEc2EllipticCurve.P521, 66, 66, 67)]
    public void Deserialize_Fails_WhenEc2CoordinateLengthIsNotTheLengthOfTheFieldElement(CoseAlgorithm alg, CoseEc2EllipticCurve crv, int expectedLength, int xLength, int yLength)
    {
        var result = _deserializer.Deserialize(Ec2CoseKey(alg, crv, TpmAttestationBuilder.Pattern(xLength, 1), TpmAttestationBuilder.Pattern(yLength, 2)));

        Assert.That(result.HasError, Is.True);
        AssertWarning($"The 'x' and 'y' coordinates of the key in EC2 format for 'crv': {crv} must each be exactly {expectedLength} bytes long (leading zero octets preserved), but 'x' is {xLength} bytes and 'y' is {yLength} bytes long");
    }

    [Test]
    public void Deserialize_Fails_WhenEc2CoordinatesArePaddedWithLeadingZeroOctet()
    {
        // the same integers as the coordinates of a valid key, encoded in 33 bytes
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var point = key.ExportParameters(false).Q;
        var paddedX = new byte[] { 0x00 }.Concat(point.X!).ToArray();
        var paddedY = new byte[] { 0x00 }.Concat(point.Y!).ToArray();

        var result = _deserializer.Deserialize(Ec2CoseKey(CoseAlgorithm.ES256, CoseEc2EllipticCurve.P256, paddedX, paddedY));

        Assert.That(result.HasError, Is.True);
        AssertWarning("The 'x' and 'y' coordinates of the key in EC2 format for 'crv': P256 must each be exactly 32 bytes long (leading zero octets preserved), but 'x' is 33 bytes and 'y' is 33 bytes long");
    }

    [Test]
    public void Deserialize_Fails_WhenEc2CoordinateLeadingZeroOctetIsStripped()
    {
        // the same integer as the 'x' coordinate of a valid key whose first octet is 0x00, encoded in 31 bytes
        using var key = P256KeyWithLeadingZeroOctetInX();
        var point = key.ExportParameters(false).Q;
        var strippedX = point.X!.Skip(1).ToArray();

        var result = _deserializer.Deserialize(Ec2CoseKey(CoseAlgorithm.ES256, CoseEc2EllipticCurve.P256, strippedX, point.Y!));

        Assert.That(result.HasError, Is.True);
        AssertWarning("The 'x' and 'y' coordinates of the key in EC2 format for 'crv': P256 must each be exactly 32 bytes long (leading zero octets preserved), but 'x' is 31 bytes and 'y' is 32 bytes long");
    }

    // ---------- OKP

    [Test]
    public void Deserialize_ReturnsOkpKey_WhenPublicKeyIs32BytesLong()
    {
        var x = TpmAttestationBuilder.Pattern(32, 1);

        var result = _deserializer.Deserialize(OkpCoseKey(CoseAlgorithm.EdDSA, CoseOkpEllipticCurve.Ed25519, x));

        var coseKey = Deserialized<CoseOkpKey>(result);
        Assert.That(coseKey.Alg, Is.EqualTo(CoseAlgorithm.EdDSA));
        Assert.That(coseKey.Crv, Is.EqualTo(CoseOkpEllipticCurve.Ed25519));
        Assert.That(coseKey.X, Is.EqualTo(x));
    }

    [TestCase(0)]
    [TestCase(31)]
    [TestCase(33)]
    [TestCase(64)]
    public void Deserialize_Fails_WhenOkpPublicKeyIsNot32BytesLong(int xLength)
    {
        var result = _deserializer.Deserialize(OkpCoseKey(CoseAlgorithm.EdDSA, CoseOkpEllipticCurve.Ed25519, TpmAttestationBuilder.Pattern(xLength, 1)));

        Assert.That(result.HasError, Is.True);
        AssertWarning($"The 'x' public key of the key in OKP format for 'crv': Ed25519 must be exactly 32 bytes long, but is {xLength} bytes long");
    }

    // ---------- RSA

    [TestCase(CoseAlgorithm.RS256)]
    [TestCase(CoseAlgorithm.PS256)]
    [TestCase(CoseAlgorithm.RS1)]
    public void Deserialize_ReturnsRsaKey_WhenParametersAreThoseOfA2048BitKey(CoseAlgorithm alg)
    {
        using var key = RSA.Create(2048);
        var parameters = key.ExportParameters(false);
        Assert.That(parameters.Modulus, Has.Length.EqualTo(256));

        var result = _deserializer.Deserialize(RsaCoseKey(alg, parameters.Modulus!, parameters.Exponent!));

        var coseKey = Deserialized<CoseRsaKey>(result);
        Assert.That(coseKey.Alg, Is.EqualTo(alg));
        Assert.That(coseKey.ModulusN, Is.EqualTo(parameters.Modulus));
        Assert.That(coseKey.ExponentE, Is.EqualTo(parameters.Exponent));
    }

    [TestCase(256, 0x80, 2048)]
    [TestCase(384, 0xFF, 3072)]
    [TestCase(2048, 0x80, 16384)]
    [TestCase(2048, 0xFF, 16384)]
    public void Deserialize_ReturnsRsaKey_WhenModulusNIsBetween2048And16384BitsLong(int modulusLength, int firstOctet, int expectedBits)
    {
        var modulus = Modulus(modulusLength, (byte) firstOctet);
        Assert.That(((modulusLength - 1) * 8) + int.Log2(firstOctet) + 1, Is.EqualTo(expectedBits));

        var result = _deserializer.Deserialize(RsaCoseKey(CoseAlgorithm.RS256, modulus, PublicExponent65537));

        var coseKey = Deserialized<CoseRsaKey>(result);
        Assert.That(coseKey.ModulusN, Is.EqualTo(modulus));
        Assert.That(coseKey.ExponentE, Is.EqualTo(PublicExponent65537));
    }

    [Test]
    public void Deserialize_ReturnsRsaKey_WhenPublicExponentEIs3()
    {
        var modulus = Modulus(256, 0xFF);

        var result = _deserializer.Deserialize(RsaCoseKey(CoseAlgorithm.RS256, modulus, new byte[] { 0x03 }));

        Assert.That(result.HasError, Is.False);
    }

    [Test]
    public void Deserialize_Fails_WhenRsaModulusNHasLeadingZeroOctet()
    {
        // the same integer as the modulus of a valid key, encoded in 257 bytes
        using var key = RSA.Create(2048);
        var parameters = key.ExportParameters(false);
        var paddedModulus = new byte[] { 0x00 }.Concat(parameters.Modulus!).ToArray();

        var result = _deserializer.Deserialize(RsaCoseKey(CoseAlgorithm.RS256, paddedModulus, parameters.Exponent!));

        Assert.That(result.HasError, Is.True);
        AssertWarning("The 'n' of the key in RSA format must be encoded with the minimum number of octets, but it is empty or starts with a 0x00 octet");
    }

    [Test]
    public void Deserialize_Fails_WhenRsaModulusNIsEmpty()
    {
        var result = _deserializer.Deserialize(RsaCoseKey(CoseAlgorithm.RS256, Array.Empty<byte>(), PublicExponent65537));

        Assert.That(result.HasError, Is.True);
        AssertWarning("The 'n' of the key in RSA format must be encoded with the minimum number of octets, but it is empty or starts with a 0x00 octet");
    }

    [TestCase(1, 0x01, 1)]
    [TestCase(64, 0xFF, 512)]
    [TestCase(128, 0x80, 1024)]
    [TestCase(255, 0xFF, 2040)]
    [TestCase(256, 0x7F, 2047)]
    [TestCase(2049, 0x01, 16385)]
    [TestCase(2049, 0xFF, 16392)]
    public void Deserialize_Fails_WhenRsaModulusNIsNotBetween2048And16384BitsLong(int modulusLength, int firstOctet, int modulusBits)
    {
        var result = _deserializer.Deserialize(RsaCoseKey(CoseAlgorithm.RS256, Modulus(modulusLength, (byte) firstOctet), PublicExponent65537));

        Assert.That(result.HasError, Is.True);
        AssertWarning($"The 'n' of the key in RSA format is {modulusBits} bits long, but must be between 2048 and 16384 bits long");
    }

    [Test]
    public void Deserialize_Fails_WhenRsaPublicExponentEIsEmpty()
    {
        var result = _deserializer.Deserialize(RsaCoseKey(CoseAlgorithm.RS256, Modulus(256, 0xFF), Array.Empty<byte>()));

        Assert.That(result.HasError, Is.True);
        AssertWarning("The 'e' of the key in RSA format must be encoded with the minimum number of octets, but it is empty or starts with a 0x00 octet");
    }

    [Test]
    public void Deserialize_Fails_WhenRsaPublicExponentEHasLeadingZeroOctet()
    {
        // 65537 encoded in 4 bytes
        var result = _deserializer.Deserialize(RsaCoseKey(CoseAlgorithm.RS256, Modulus(256, 0xFF), new byte[] { 0x00, 0x01, 0x00, 0x01 }));

        Assert.That(result.HasError, Is.True);
        AssertWarning("The 'e' of the key in RSA format must be encoded with the minimum number of octets, but it is empty or starts with a 0x00 octet");
    }

    [TestCase(new byte[] { 0x02 })]
    [TestCase(new byte[] { 0x01, 0x00, 0x00 })]
    [TestCase(new byte[] { 0x01, 0x00, 0x02 })]
    public void Deserialize_Fails_WhenRsaPublicExponentEIsEven(byte[] publicExponent)
    {
        var result = _deserializer.Deserialize(RsaCoseKey(CoseAlgorithm.RS256, Modulus(256, 0xFF), publicExponent));

        Assert.That(result.HasError, Is.True);
        AssertWarning("The 'e' of the key in RSA format must be odd");
    }

    [Test]
    public void Deserialize_Fails_WhenRsaPublicExponentEIs1()
    {
        var result = _deserializer.Deserialize(RsaCoseKey(CoseAlgorithm.RS256, Modulus(256, 0xFF), new byte[] { 0x01 }));

        Assert.That(result.HasError, Is.True);
        AssertWarning("The 'e' of the key in RSA format must be greater than 1");
    }

    [TestCase(256)]
    [TestCase(300)]
    public void Deserialize_Fails_WhenRsaPublicExponentEIsNotShorterThanModulusN(int exponentLength)
    {
        var publicExponent = TpmAttestationBuilder.Pattern(exponentLength, 1);
        publicExponent[0] = 0x01;
        publicExponent[^1] |= 0x01;

        var result = _deserializer.Deserialize(RsaCoseKey(CoseAlgorithm.RS256, Modulus(256, 0xFF), publicExponent));

        Assert.That(result.HasError, Is.True);
        AssertWarning($"The 'e' of the key in RSA format ({exponentLength} bytes) must be shorter than the 'n' (256 bytes)");
    }

    // ---------- helpers

    private void AssertWarning(string message)
    {
        Assert.That(_logger.Entries.Select(entry => (entry.Level, entry.Message)), Does.Contain((LogLevel.Warning, message)));
    }

    private static TCoseKey Deserialized<TCoseKey>(Result<SuccessfulCoseKeyDeserializeResult> result) where TCoseKey : AbstractCoseKey
    {
        Assert.That(result.HasError, Is.False);
        Assert.That(result.Ok?.CoseKey, Is.InstanceOf<TCoseKey>());
        return (TCoseKey) result.Ok!.CoseKey;
    }

    private static byte[] Ec2CoseKey(CoseAlgorithm alg, CoseEc2EllipticCurve crv, byte[] x, byte[] y)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(5);
        writer.WriteInt32(1); // kty
        writer.WriteInt32(2); // EC2
        writer.WriteInt32(3); // alg
        writer.WriteInt32((int) alg);
        writer.WriteInt32(-1); // crv
        writer.WriteInt32((int) crv);
        writer.WriteInt32(-2); // x
        writer.WriteByteString(x);
        writer.WriteInt32(-3); // y
        writer.WriteByteString(y);
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] RsaCoseKey(CoseAlgorithm alg, byte[] n, byte[] e)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(4);
        writer.WriteInt32(1); // kty
        writer.WriteInt32(3); // RSA
        writer.WriteInt32(3); // alg
        writer.WriteInt32((int) alg);
        writer.WriteInt32(-1); // n
        writer.WriteByteString(n);
        writer.WriteInt32(-2); // e
        writer.WriteByteString(e);
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] OkpCoseKey(CoseAlgorithm alg, CoseOkpEllipticCurve crv, byte[] x)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(4);
        writer.WriteInt32(1); // kty
        writer.WriteInt32(1); // OKP
        writer.WriteInt32(3); // alg
        writer.WriteInt32((int) alg);
        writer.WriteInt32(-1); // crv
        writer.WriteInt32((int) crv);
        writer.WriteInt32(-2); // x
        writer.WriteByteString(x);
        writer.WriteEndMap();
        return writer.Encode();
    }

    // an odd big-endian integer of the given length whose first octet is the given one
    private static byte[] Modulus(int length, byte firstOctet)
    {
        var modulus = TpmAttestationBuilder.Pattern(length, 3);
        modulus[0] = firstOctet;
        modulus[^1] |= 0x01;
        return modulus;
    }

    private static ECDsa P256KeyWithLeadingZeroOctetInX()
    {
        // about one key in 256 has an 'x' coordinate whose first octet is 0x00
        for (var i = 0; i < 10000; i++)
        {
            var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            if (key.ExportParameters(false).Q.X![0] == 0x00)
            {
                return key;
            }

            key.Dispose();
        }

        throw new InvalidOperationException("No P-256 key with a leading zero octet in 'x' was generated");
    }

    private static ECCurve ToECCurve(CoseEc2EllipticCurve crv)
    {
        return crv switch
        {
            CoseEc2EllipticCurve.P256 => ECCurve.NamedCurves.nistP256,
            CoseEc2EllipticCurve.P384 => ECCurve.NamedCurves.nistP384,
            CoseEc2EllipticCurve.P521 => ECCurve.NamedCurves.nistP521,
            _ => throw new ArgumentOutOfRangeException(nameof(crv))
        };
    }
}
