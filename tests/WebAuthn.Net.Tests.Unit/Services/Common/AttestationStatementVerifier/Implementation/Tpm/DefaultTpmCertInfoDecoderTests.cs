using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using NUnit.Framework;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;

public class DefaultTpmCertInfoDecoderTests
{
    // TPM 2.0 Library Part 2, Version 185, Table 7: TPM_GENERATED_VALUE
    private const uint TpmGeneratedValue = 0xff544347;

    // TPM 2.0 Library Part 2, Version 185, Table 21: TPM_ST_ATTEST_CERTIFY
    private const ushort TpmStAttestCertify = 0x8017;

    // TPM 2.0 Library Part 2, Version 185, Table 8: TPM_ALG_SHA256
    private const int TpmAlgSha256 = 0x000B;

    private const ulong Clock = 1_000_000UL;

    // obfuscated values, as in the real test vectors (the Windows AIK is not in the Endorsement or Platform hierarchy)
    private const uint ResetCount = 0xcddf6e18;
    private const uint RestartCount = 0x07a22498;
    private const ulong FirmwareVersion = 0x0000000200000000UL;

    [Test]
    public void DecodeTpm2BName_DecodesEmptyName_WhenSizeIsZero()
    {
        var decoder = new DefaultTpmCertInfoDecoder();
        Span<byte> buffer = new byte[] { 0x00, 0x00 };

        var result = decoder.DecodeTpm2BName(ref buffer);
        var remaining = buffer.Length;

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.Digest, Is.Null);
            Assert.That(result.Ok?.Handle, Is.Null);
            Assert.That(remaining, Is.Zero);
        });
    }

    [Test]
    public void DecodeTpm2BName_DecodesHandle_WhenSizeIsFour()
    {
        var decoder = new DefaultTpmCertInfoDecoder();
        // TPM_RH_NULL (0x40000007) - the qualifiedSigner of a TPMS_ATTEST signed with the NULL key
        Span<byte> buffer = new byte[] { 0x00, 0x04, 0x40, 0x00, 0x00, 0x07 };

        var result = decoder.DecodeTpm2BName(ref buffer);
        var remaining = buffer.Length;

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.Digest, Is.Null);
            Assert.That(result.Ok?.Handle?.Handle, Is.EqualTo(0x40000007u));
            Assert.That(remaining, Is.Zero);
        });
    }

    // TPM 2.0 Library Part 2, Version 185, Table 88 (TPMU_HA): the digest size is fixed per algorithm,
    // so the only valid digest-form sizes of a TPM2B_NAME are 22, 26, 34, 50 and 66
    // TPM_ALG_SHA1
    [TestCase(0x0004, 20)]
    // TPM_ALG_SHA256
    [TestCase(0x000B, 32)]
    // TPM_ALG_SHA384
    [TestCase(0x000C, 48)]
    // TPM_ALG_SHA512
    [TestCase(0x000D, 64)]
    // TPM_ALG_SHA256_192
    [TestCase(0x000E, 24)]
    // TPM_ALG_SM3_256
    [TestCase(0x0012, 32)]
    // TPM_ALG_SHA3_256
    [TestCase(0x0027, 32)]
    // TPM_ALG_SHA3_384
    [TestCase(0x0028, 48)]
    // TPM_ALG_SHA3_512
    [TestCase(0x0029, 64)]
    // TPM_ALG_SHAKE256_192
    [TestCase(0x002C, 24)]
    // TPM_ALG_SHAKE256_256
    [TestCase(0x002D, 32)]
    // TPM_ALG_SHAKE256_512
    [TestCase(0x002E, 64)]
    public void DecodeTpm2BName_DecodesDigest_WhenSizeMatchesHashAlgorithm(int hashAlg, int digestSize)
    {
        var decoder = new DefaultTpmCertInfoDecoder();
        var expectedDigest = Pattern(digestSize);
        Span<byte> buffer = BuildName(2 + digestSize, hashAlg, expectedDigest);

        var result = decoder.DecodeTpm2BName(ref buffer);
        var remaining = buffer.Length;

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.Handle, Is.Null);
            Assert.That(result.Ok?.Digest?.HashAlg, Is.EqualTo((TpmAlgIdHash) hashAlg));
            Assert.That(result.Ok?.Digest?.Digest, Is.EqualTo(expectedDigest));
            Assert.That(remaining, Is.Zero);
        });
    }

    [TestCase(1)]
    [TestCase(2)]
    [TestCase(3)]
    public void DecodeTpm2BName_Fails_WhenSizeIsBetweenOneAndThree(int size)
    {
        var decoder = new DefaultTpmCertInfoDecoder();
        // enough trailing octets for any of these sizes, so the rejection is caused by the size rule and not by a truncated buffer
        var bytes = new byte[2 + 4];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, (ushort) size);
        Span<byte> buffer = bytes;

        var result = decoder.DecodeTpm2BName(ref buffer);

        Assert.That(result.HasError, Is.True);
    }

    // size 5: TPM_ALG_SHA256 followed by 3 octets
    [TestCase(5, 0x000B, 3)]
    // size 35: TPM_ALG_SHA256 followed by 33 octets
    [TestCase(35, 0x000B, 33)]
    // size 67: TPM_ALG_SHA512 followed by 65 octets (also larger than sizeof(TPMU_NAME))
    [TestCase(67, 0x000D, 65)]
    // size 22 with TPM_ALG_SHA256: a SHA-256 Name is 34 octets
    [TestCase(22, 0x000B, 20)]
    // size 34 with TPM_ALG_SHA1: a SHA-1 Name is 22 octets
    [TestCase(34, 0x0004, 32)]
    // size 66 with TPM_ALG_SHA384: a SHA-384 Name is 50 octets
    [TestCase(66, 0x000C, 64)]
    public void DecodeTpm2BName_Fails_WhenSizeDoesNotMatchHashAlgorithm(int size, int hashAlg, int digestLength)
    {
        var decoder = new DefaultTpmCertInfoDecoder();
        Span<byte> buffer = BuildName(size, hashAlg, Pattern(digestLength));

        var result = decoder.DecodeTpm2BName(ref buffer);

        Assert.That(result.HasError, Is.True);
    }

    // TPM_ALG_NULL: never forms a Name (the reference implementation produces an empty Name instead)
    [TestCase(0x0010)]
    // TPM_ALG_RSA: not a hash algorithm
    [TestCase(0x0001)]
    // TPM_ALG_HMAC: not a hash algorithm
    [TestCase(0x0005)]
    // TPM_ALG_KEYEDHASH: not a hash algorithm
    [TestCase(0x0008)]
    // TPM_ALG_ECC: not a hash algorithm
    [TestCase(0x0023)]
    // not assigned by the TCG
    [TestCase(0xFFFF)]
    public void DecodeTpm2BName_Fails_WhenHashAlgorithmIsUnknown(int hashAlg)
    {
        var decoder = new DefaultTpmCertInfoDecoder();
        Span<byte> buffer = BuildName(34, hashAlg, Pattern(32));

        var result = decoder.DecodeTpm2BName(ref buffer);

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public void DecodeTpm2BName_Fails_WhenBufferIsShorterThanSize()
    {
        var decoder = new DefaultTpmCertInfoDecoder();
        Span<byte> buffer = BuildName(34, TpmAlgSha256, Pattern(10));

        var result = decoder.DecodeTpm2BName(ref buffer);

        Assert.That(result.HasError, Is.True);
    }

    [TestCase(0)]
    [TestCase(1)]
    public void DecodeTpm2BName_Fails_WhenBufferIsShorterThanSizeField(int length)
    {
        var decoder = new DefaultTpmCertInfoDecoder();
        Span<byte> buffer = new byte[length];

        var result = decoder.DecodeTpm2BName(ref buffer);

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public void Decode_DecodesAllFields_WhenCertInfoIsWellFormed()
    {
        var decoder = new DefaultTpmCertInfoDecoder();
        var extraData = Pattern(20);
        var certInfo = BuildCertInfo(extraData);

        var result = decoder.Decode(certInfo);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.QualifiedSigner.Handle, Is.Null);
            Assert.That(result.Ok?.QualifiedSigner.Digest?.HashAlg, Is.EqualTo(TpmAlgIdHash.Sha256));
            Assert.That(result.Ok?.QualifiedSigner.Digest?.Digest, Is.EqualTo(Pattern(32)));
            Assert.That(result.Ok?.ExtraData, Is.EqualTo(extraData));
            Assert.That(result.Ok?.Clock, Is.EqualTo(Clock));
            Assert.That(result.Ok?.ResetCount, Is.EqualTo(ResetCount));
            Assert.That(result.Ok?.RestartCount, Is.EqualTo(RestartCount));
            Assert.That(result.Ok?.Safe, Is.True);
            Assert.That(result.Ok?.FirmwareVersion, Is.EqualTo(FirmwareVersion));
            Assert.That(result.Ok?.Attested.Certify.Name.Digest?.HashAlg, Is.EqualTo(TpmAlgIdHash.Sha256));
            Assert.That(result.Ok?.Attested.Certify.Name.Digest?.Digest, Is.EqualTo(Pattern(32)));
            Assert.That(result.Ok?.Attested.Certify.QualifiedName.Digest?.HashAlg, Is.EqualTo(TpmAlgIdHash.Sha256));
            Assert.That(result.Ok?.Attested.Certify.QualifiedName.Digest?.Digest, Is.EqualTo(Pattern(32)));
        });
    }

    [TestCase(0)]
    [TestCase(20)]
    [TestCase(32)]
    [TestCase(64)]
    // sizeof(TPMT_HA) = 2 + 64: the largest extraData a TPM accepts (TPM 2.0 Library Part 2, Version 185, Table 91; TPM2B_DATA_Unmarshal)
    [TestCase(66)]
    public void Decode_DecodesCertInfo_WhenExtraDataIsNotLargerThanTpmtHa(int extraDataSize)
    {
        var decoder = new DefaultTpmCertInfoDecoder();
        var extraData = Pattern(extraDataSize);
        var certInfo = BuildCertInfo(extraData);

        var result = decoder.Decode(certInfo);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.ExtraData, Is.EqualTo(extraData));
        });
    }

    [TestCase(67)]
    [TestCase(1024)]
    public void Decode_Fails_WhenExtraDataIsLargerThanTpmtHa(int extraDataSize)
    {
        var decoder = new DefaultTpmCertInfoDecoder();
        var certInfo = BuildCertInfo(Pattern(extraDataSize));

        var result = decoder.Decode(certInfo);

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public void Decode_Fails_WhenTrailingBytesArePresent()
    {
        var decoder = new DefaultTpmCertInfoDecoder();
        var certInfo = BuildCertInfo(Pattern(20));
        var certInfoWithTrailingByte = new byte[certInfo.Length + 1];
        certInfo.CopyTo(certInfoWithTrailingByte, 0);

        var result = decoder.Decode(certInfoWithTrailingByte);

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public void Decode_Fails_WhenCertInfoIsTruncated()
    {
        var decoder = new DefaultTpmCertInfoDecoder();
        var certInfo = BuildCertInfo(Pattern(20));

        var result = decoder.Decode(certInfo.AsSpan(0, certInfo.Length - 1));

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public void Decode_Fails_WhenMagicIsNotTpmGeneratedValue()
    {
        var decoder = new DefaultTpmCertInfoDecoder();
        var certInfo = BuildCertInfo(Pattern(20), magic: 0xff544348);

        var result = decoder.Decode(certInfo);

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public void Decode_Fails_WhenTypeIsNotTpmStAttestCertify()
    {
        var decoder = new DefaultTpmCertInfoDecoder();
        // TPM_ST_ATTEST_QUOTE
        var certInfo = BuildCertInfo(Pattern(20), type: 0x8018);

        var result = decoder.Decode(certInfo);

        Assert.That(result.HasError, Is.True);
    }

    [TestCase(2)]
    [TestCase(0xFF)]
    public void Decode_Fails_WhenSafeIsNeitherYesNorNo(int safe)
    {
        var decoder = new DefaultTpmCertInfoDecoder();
        var certInfo = BuildCertInfo(Pattern(20), safe: (byte) safe);

        var result = decoder.Decode(certInfo);

        Assert.That(result.HasError, Is.True);
    }

    private static byte[] Pattern(int length)
    {
        var result = new byte[length];
        for (var i = 0; i < length; i++)
        {
            result[i] = (byte) (i + 1);
        }

        return result;
    }

    // TPM2B_NAME (TPM 2.0 Library Part 2, Version 185, Table 105): size || hashAlg || digest, with an explicit size so that malformed sizes can be produced
    private static byte[] BuildName(int size, int hashAlg, byte[] digest)
    {
        var result = new byte[2 + 2 + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(0, 2), (ushort) size);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2, 2), (ushort) hashAlg);
        digest.CopyTo(result.AsSpan(4));
        return result;
    }

    // TPMS_ATTEST (TPM 2.0 Library Part 2, Version 185, Table 154) with type = TPM_ST_ATTEST_CERTIFY;
    // every Name is TPM_ALG_SHA256 || 32 octets, as in the real test vectors
    private static byte[] BuildCertInfo(byte[] extraData, uint magic = TpmGeneratedValue, ushort type = TpmStAttestCertify, byte safe = 0x01)
    {
        var name = BuildName(34, TpmAlgSha256, Pattern(32));
        var result = new List<byte>();
        AddBigEndian(result, magic, 4); // magic
        AddBigEndian(result, type, 2); // type
        result.AddRange(name); // qualifiedSigner
        AddBigEndian(result, (ulong) extraData.Length, 2); // extraData.size
        result.AddRange(extraData); // extraData.buffer
        AddBigEndian(result, Clock, 8); // clockInfo.clock
        AddBigEndian(result, ResetCount, 4); // clockInfo.resetCount
        AddBigEndian(result, RestartCount, 4); // clockInfo.restartCount
        result.Add(safe); // clockInfo.safe
        AddBigEndian(result, FirmwareVersion, 8); // firmwareVersion
        result.AddRange(name); // attested.certify.name
        result.AddRange(name); // attested.certify.qualifiedName
        return result.ToArray();
    }

    private static void AddBigEndian(List<byte> target, ulong value, int byteCount)
    {
        for (var i = byteCount - 1; i >= 0; i--)
        {
            target.Add((byte) (value >> (8 * i)));
        }
    }
}
