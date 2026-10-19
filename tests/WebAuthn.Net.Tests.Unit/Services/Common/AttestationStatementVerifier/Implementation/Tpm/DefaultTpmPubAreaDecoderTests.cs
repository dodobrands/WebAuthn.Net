using System;
using System.Buffers.Binary;
using NUnit.Framework;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;

public class DefaultTpmPubAreaDecoderTests
{
    // Real "pubArea" of a Windows Hello (AMD fTPM) RSA credential: the attStmt of tests/WebAuthn.Net.Tests.Unit/TestVectors/Tpm/Rsa/regResponse.json
    // (the same attestation object is embedded in DefaultRegistrationCeremonyServiceTpmTests).
    // Layout (byte offsets): type 0x0001 @0, nameAlg 0x000B (SHA-256) @2, objectAttributes 0x00060472 @4, authPolicy.size 32 @8, authPolicy @10..41,
    // symmetric TPM_ALG_NULL @42, scheme TPM_ALG_NULL @44, keyBits 2048 @46, exponent 0 @48, unique.size 256 @52, unique.buffer (modulus, first byte 0xC5) @54..309.
    private const string RsaPubAreaHex =
        "0001000b0006047200209dffcbf36c383ae699fb9868dc6dcb89d7153884be2803922c124158bfad22ae001000100800000000000100c50d45a8896ddcc93175535fc95f1c3b2d7a540e03390bdc93dcc9edb600e2fa"
        + "90975162b2fee563cb4d5834f063339995018da7deed4166e0b2c1728c235e2b17d94fef95f7c1cae095f8d3f078c92cc241050cb36f9f74545e8937f2194cb20aaeef00041ec00b41c670443d3a1b185513c6edb41e"
        + "f4869032b59b2eef962e7c4a0b491b05b8b05821d5d325038e5c33afd655803a6e0e950f705c35291db39caaf796a23bc62821acd4d9bb739e86b4392aa53ba8feea63e6e602b8c092a272232083bc732c9cf5deb0b2"
        + "d0d731a7a48decba8864ae78cfd216c3674ef8138660224d2a0f14f308c6f1546159fde4e70c07144466fbfc27ff2d29ae4450cb";

    // Real "pubArea" of a Windows Hello (AMD fTPM) ECDSA P-256 credential: the attStmt of tests/WebAuthn.Net.Tests.Unit/TestVectors/Tpm/Ecdsa/regResponse.json.
    // Layout (byte offsets): type 0x0023 @0, nameAlg 0x000B (SHA-256) @2, objectAttributes 0x00040072 @4, authPolicy.size 32 @8, authPolicy @10..41,
    // symmetric TPM_ALG_NULL @42, scheme TPM_ALG_NULL @44, curveID 0x0003 (P-256) @46, kdf TPM_ALG_NULL @48, x.size 32 @50, x @52..83, y.size 32 @84, y @86..117.
    private const string EccPubAreaHex =
        "0023000b0004007200209dffcbf36c383ae699fb9868dc6dcb89d7153884be2803922c124158bfad22ae001000100003001000202cbfdae1ed97edab5ee5c271557930fcff24450b4b457ccd549c510ef7a112820020edecd82e819f367cc60e07b7d7802439ea72d6330f42483a6abc4aef819c375c";

    // Offsets shared by both vectors
    private const int TypeOffset = 0;
    private const int NameAlgOffset = 2;
    private const int ObjectAttributesOffset = 4;
    private const int AuthPolicySizeOffset = 8;
    private const int AuthPolicyOffset = 10;
    private const int AuthPolicyLength = 32;
    private const int SymmetricOffset = 42;
    private const int SchemeOffset = 44;
    private const int SchemeDetailsOffset = 46;

    // RSA vector offsets
    private const int RsaKeyBitsOffset = 46;
    private const int RsaExponentOffset = 48;
    private const int RsaUniqueSizeOffset = 52;
    private const int RsaModulusOffset = 54;
    private const int RsaModulusLength = 256;

    // ECC vector offsets
    private const int EccCurveIdOffset = 46;
    private const int EccKdfOffset = 48;
    private const int EccXSizeOffset = 50;
    private const int EccXOffset = 52;
    private const int EccYSizeOffset = 84;
    private const int EccYOffset = 86;
    private const int EccCoordinateLength = 32;

    // TPMA_OBJECT values of the vectors
    private const uint RsaObjectAttributes = 0x00060472; // fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | noDA | decrypt | sign
    private const uint EccObjectAttributes = 0x00040072; // fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | sign
    private const uint FixedTpmBit = 1u << 1;
    private const uint FixedParentBit = 1u << 4;
    private const uint FirmwareLimitedBit = 1u << 8;
    private const uint SvnLimitedBit = 1u << 9;
    private const uint EncryptedDuplicationBit = 1u << 11;
    private const uint RestrictedBit = 1u << 16;
    private const uint DecryptBit = 1u << 17;
    private const uint SignBit = 1u << 18;
    private const uint X509SignBit = 1u << 19;

    // TPM_ALG_ID values used by the mutations
    private const ushort TpmAlgNull = 0x0010;
    private const ushort TpmAlgSha1 = 0x0004;
    private const ushort TpmAlgSha256 = 0x000B;
    private const ushort TpmAlgSha384 = 0x000C;
    private const ushort TpmAlgAes = 0x0006;
    private const ushort TpmAlgRsassa = 0x0014;
    private const ushort TpmAlgRsaes = 0x0015;
    private const ushort TpmAlgRsapss = 0x0016;
    private const ushort TpmAlgOaep = 0x0017;
    private const ushort TpmAlgEcdsa = 0x0018;
    private const ushort TpmAlgEcdh = 0x0019;
    private const ushort TpmAlgEcdaa = 0x001A;
    private const ushort TpmAlgSm2 = 0x001B;
    private const ushort TpmAlgEcschnorr = 0x001C;
    private const ushort TpmAlgEcmqv = 0x001D;
    private const ushort TpmAlgEddsa = 0x0060;
    private const ushort TpmAlgHashEddsa = 0x0061;
    private const ushort TpmAlgMgf1 = 0x0007;
    private const ushort TpmAlgHkdf = 0x001F;
    private const ushort TpmAlgKdf1Sp80056A = 0x0020;

    private DefaultTpmPubAreaDecoder Decoder { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        Decoder = new();
    }

    // ---------------------------------------------------------------------------------------------
    // Positive: the real vectors decode and expose every field WebAuthn needs

    [Test]
    public void DefaultTpmPubAreaDecoder_DecodesRsaPubArea_WhenRealWindowsHelloRsaVector()
    {
        var rsaPubArea = Convert.FromHexString(RsaPubAreaHex);

        var pubArea = DecodeSuccessfully(rsaPubArea);

        Assert.That(pubArea.Type, Is.EqualTo(TpmAlgPublic.Rsa));
        Assert.That(pubArea.NameAlg, Is.EqualTo(TpmAlgIdHash.Sha256));
        Assert.That(pubArea.ObjectAttributes, Is.EqualTo((ObjectAttributes) RsaObjectAttributes));
        Assert.That(
            pubArea.ObjectAttributes,
            Is.EqualTo(ObjectAttributes.FixedTpm | ObjectAttributes.FixedParent | ObjectAttributes.SensitiveDataOrigin | ObjectAttributes.UserWithAuth | ObjectAttributes.NoDa | ObjectAttributes.Decrypt | ObjectAttributes.SignEncrypt));
        Assert.That(pubArea.Parameters, Is.InstanceOf<RsaParms>());
        var rsaParms = (RsaParms) pubArea.Parameters;
        Assert.That(rsaParms.KeyBits, Is.EqualTo(2048));
        Assert.That(rsaParms.Exponent, Is.EqualTo(65537U));
        Assert.That(pubArea.Unique, Is.InstanceOf<RsaUnique>());
        var rsaUnique = (RsaUnique) pubArea.Unique;
        Assert.That(rsaUnique.Buffer, Has.Length.EqualTo(RsaModulusLength));
        Assert.That(rsaUnique.Buffer, Is.EqualTo(rsaPubArea.AsSpan(RsaModulusOffset, RsaModulusLength).ToArray()));
        Assert.That(rsaUnique.Buffer[0], Is.EqualTo(0xC5));
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_DecodesEccPubArea_WhenRealWindowsHelloEcdsaVector()
    {
        var eccPubArea = Convert.FromHexString(EccPubAreaHex);

        var pubArea = DecodeSuccessfully(eccPubArea);

        Assert.That(pubArea.Type, Is.EqualTo(TpmAlgPublic.Ecc));
        Assert.That(pubArea.NameAlg, Is.EqualTo(TpmAlgIdHash.Sha256));
        Assert.That(pubArea.ObjectAttributes, Is.EqualTo((ObjectAttributes) EccObjectAttributes));
        Assert.That(
            pubArea.ObjectAttributes,
            Is.EqualTo(ObjectAttributes.FixedTpm | ObjectAttributes.FixedParent | ObjectAttributes.SensitiveDataOrigin | ObjectAttributes.UserWithAuth | ObjectAttributes.SignEncrypt));
        Assert.That(pubArea.Parameters, Is.InstanceOf<EccParms>());
        var eccParms = (EccParms) pubArea.Parameters;
        Assert.That(eccParms.CurveId, Is.EqualTo(TpmiEccCurve.TpmEccNistP256));
        Assert.That(pubArea.Unique, Is.InstanceOf<EccUnique>());
        var eccUnique = (EccUnique) pubArea.Unique;
        Assert.That(eccUnique.X, Is.EqualTo(eccPubArea.AsSpan(EccXOffset, EccCoordinateLength).ToArray()));
        Assert.That(eccUnique.Y, Is.EqualTo(eccPubArea.AsSpan(EccYOffset, EccCoordinateLength).ToArray()));
    }

    // ---------------------------------------------------------------------------------------------
    // TPMT_PUBLIC header: type, nameAlg, objectAttributes, authPolicy

    [TestCase(RsaPubAreaHex, 0x0008)] // TPM_ALG_KEYEDHASH
    [TestCase(RsaPubAreaHex, 0x0025)] // TPM_ALG_SYMCIPHER
    [TestCase(RsaPubAreaHex, 0x00A1)] // TPM_ALG_MLDSA
    [TestCase(EccPubAreaHex, 0x0008)]
    [TestCase(EccPubAreaHex, 0x0000)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenTypeIsNotRsaOrEcc(string pubAreaHex, int type)
    {
        var pubArea = WithUInt16(Convert.FromHexString(pubAreaHex), TypeOffset, (ushort) type);

        AssertFails(pubArea);
    }

    [TestCase(RsaPubAreaHex)]
    [TestCase(EccPubAreaHex)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenNameAlgIsNull(string pubAreaHex)
    {
        // with an empty authPolicy, so that only the nameAlg rule can reject it (a 32-byte authPolicy would also fail the authPolicy size rule)
        var pubArea = WithUInt16(WithEmptyAuthPolicy(Convert.FromHexString(pubAreaHex)), NameAlgOffset, TpmAlgNull);

        AssertFails(pubArea);
    }

    [TestCase(RsaPubAreaHex, 0x0003)] // TPM_ALG_TDES, not a hash
    [TestCase(RsaPubAreaHex, 0x0000)]
    [TestCase(EccPubAreaHex, 0xFFFF)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenNameAlgIsUnknown(string pubAreaHex, int nameAlg)
    {
        // with an empty authPolicy, so that only the nameAlg rule can reject it
        var pubArea = WithUInt16(WithEmptyAuthPolicy(Convert.FromHexString(pubAreaHex)), NameAlgOffset, (ushort) nameAlg);

        AssertFails(pubArea);
    }

    [TestCase(RsaPubAreaHex, 1u << 0)]
    [TestCase(RsaPubAreaHex, 1u << 12)]
    [TestCase(RsaPubAreaHex, 1u << 15)]
    [TestCase(RsaPubAreaHex, 1u << 20)]
    [TestCase(RsaPubAreaHex, 1u << 31)]
    [TestCase(EccPubAreaHex, 1u << 0)]
    [TestCase(EccPubAreaHex, 1u << 13)]
    [TestCase(EccPubAreaHex, 1u << 14)]
    [TestCase(EccPubAreaHex, 1u << 21)]
    [TestCase(EccPubAreaHex, 1u << 22)]
    [TestCase(EccPubAreaHex, 1u << 23)]
    [TestCase(EccPubAreaHex, 1u << 24)]
    [TestCase(EccPubAreaHex, 1u << 25)]
    [TestCase(EccPubAreaHex, 1u << 26)]
    [TestCase(EccPubAreaHex, 1u << 27)]
    [TestCase(EccPubAreaHex, 1u << 28)]
    [TestCase(EccPubAreaHex, 1u << 29)]
    [TestCase(EccPubAreaHex, 1u << 30)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenReservedObjectAttributeBitIsSet(string pubAreaHex, uint reservedBit)
    {
        var source = Convert.FromHexString(pubAreaHex);
        var attributes = BinaryPrimitives.ReadUInt32BigEndian(source.AsSpan(ObjectAttributesOffset, 4));
        var pubArea = WithUInt32(source, ObjectAttributesOffset, attributes | reservedBit);

        AssertFails(pubArea);
    }

    [TestCase(RsaPubAreaHex)]
    [TestCase(EccPubAreaHex)]
    public void DefaultTpmPubAreaDecoder_Succeeds_WhenObjectAttributeBit3IsSet(string pubAreaHex)
    {
        // Bit 3 is reserved in the published Table 37 but not in the reference implementation's mask (0xFFF0F001, stale TPMA_OBJECT_fixedFirmware); the reference mask is used.
        var source = Convert.FromHexString(pubAreaHex);
        var attributes = BinaryPrimitives.ReadUInt32BigEndian(source.AsSpan(ObjectAttributesOffset, 4));
        var pubArea = WithUInt32(source, ObjectAttributesOffset, attributes | (1u << 3));

        var decoded = DecodeSuccessfully(pubArea);

        Assert.That((uint) decoded.ObjectAttributes & (1u << 3), Is.EqualTo(1u << 3));
    }

    [TestCase(RsaPubAreaHex)]
    [TestCase(EccPubAreaHex)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenAuthPolicyIsOneByteShorterThanNameAlgDigest(string pubAreaHex)
    {
        // size = 31 with a 31-byte policy: structurally consistent, only the "digest size of nameAlg" rule rejects it
        var source = Convert.FromHexString(pubAreaHex);
        var pubArea = WithUInt16(Remove(source, AuthPolicyOffset, 1), AuthPolicySizeOffset, AuthPolicyLength - 1);

        AssertFails(pubArea);
    }

    [TestCase(RsaPubAreaHex)]
    [TestCase(EccPubAreaHex)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenAuthPolicyIsOneByteLongerThanNameAlgDigest(string pubAreaHex)
    {
        var source = Convert.FromHexString(pubAreaHex);
        var pubArea = WithUInt16(InsertByte(source, AuthPolicyOffset, 0x00), AuthPolicySizeOffset, AuthPolicyLength + 1);

        AssertFails(pubArea);
    }

    [TestCase(RsaPubAreaHex)]
    [TestCase(EccPubAreaHex)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenNameAlgDigestSizeDoesNotMatchAuthPolicySize(string pubAreaHex)
    {
        // SHA-384 nameAlg with the 32-byte policy of the vector
        var pubArea = WithUInt16(Convert.FromHexString(pubAreaHex), NameAlgOffset, TpmAlgSha384);

        AssertFails(pubArea);
    }

    [TestCase(RsaPubAreaHex)]
    [TestCase(EccPubAreaHex)]
    public void DefaultTpmPubAreaDecoder_Succeeds_WhenAuthPolicyIsEmpty(string pubAreaHex)
    {
        var source = Convert.FromHexString(pubAreaHex);
        var pubArea = WithUInt16(Remove(source, AuthPolicyOffset, AuthPolicyLength), AuthPolicySizeOffset, 0);

        var decoded = DecodeSuccessfully(pubArea);

        Assert.That(decoded.NameAlg, Is.EqualTo(TpmAlgIdHash.Sha256));
    }

    [TestCase(RsaPubAreaHex)]
    [TestCase(EccPubAreaHex)]
    public void DefaultTpmPubAreaDecoder_Succeeds_WhenNameAlgIsSha384AndAuthPolicyIsEmpty(string pubAreaHex)
    {
        var source = Convert.FromHexString(pubAreaHex);
        var pubArea = WithUInt16(WithUInt16(Remove(source, AuthPolicyOffset, AuthPolicyLength), AuthPolicySizeOffset, 0), NameAlgOffset, TpmAlgSha384);

        var decoded = DecodeSuccessfully(pubArea);

        Assert.That(decoded.NameAlg, Is.EqualTo(TpmAlgIdHash.Sha384));
    }

    [TestCase(RsaPubAreaHex)]
    [TestCase(EccPubAreaHex)]
    public void DefaultTpmPubAreaDecoder_Succeeds_WhenNameAlgIsSha1AndAuthPolicyIsSha1Sized(string pubAreaHex)
    {
        // SHA-1 is deprecated since version 184 but still produced by deployed TPMs; a 20-byte policy matches its digest size
        var source = Convert.FromHexString(pubAreaHex);
        var pubArea = WithUInt16(WithUInt16(Remove(source, AuthPolicyOffset, AuthPolicyLength - 20), AuthPolicySizeOffset, 20), NameAlgOffset, TpmAlgSha1);

        var decoded = DecodeSuccessfully(pubArea);

        Assert.That(decoded.NameAlg, Is.EqualTo(TpmAlgIdHash.Sha1));
    }

    [TestCase(RsaPubAreaHex)]
    [TestCase(EccPubAreaHex)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenSignIsClear(string pubAreaHex)
    {
        // RSA vector becomes a decrypt-only key, ECC vector a key with neither sign nor decrypt: neither can be a WebAuthn credential key
        var source = Convert.FromHexString(pubAreaHex);
        var attributes = BinaryPrimitives.ReadUInt32BigEndian(source.AsSpan(ObjectAttributesOffset, 4));
        var pubArea = WithUInt32(source, ObjectAttributesOffset, attributes & ~SignBit);

        AssertFails(pubArea);
    }

    [TestCase(RsaPubAreaHex)]
    [TestCase(EccPubAreaHex)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenSymmetricIsNotNull(string pubAreaHex)
    {
        var pubArea = WithUInt16(Convert.FromHexString(pubAreaHex), SymmetricOffset, TpmAlgAes);

        AssertFails(pubArea);
    }

    [TestCase(RsaPubAreaHex)]
    [TestCase(EccPubAreaHex)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenTrailingByteIsPresent(string pubAreaHex)
    {
        var source = Convert.FromHexString(pubAreaHex);
        var pubArea = InsertByte(source, source.Length, 0x00);

        AssertFails(pubArea);
    }

    [TestCase(RsaPubAreaHex)]
    [TestCase(EccPubAreaHex)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenTruncated(string pubAreaHex)
    {
        var source = Convert.FromHexString(pubAreaHex);

        for (var length = 0; length < source.Length; length++)
        {
            var truncated = source.AsSpan(0, length).ToArray();
            var result = Decoder.Decode(truncated);
            Assert.That(result.HasError, Is.True, $"A pubArea truncated to {length} bytes must not decode");
        }
    }

    // ---------------------------------------------------------------------------------------------
    // RSA: TPMS_RSA_PARMS and TPM2B_PUBLIC_KEY_RSA

    [TestCase(1024)]
    [TestCase(3072)]
    [TestCase(4096)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenRsaKeyBitsDoNotMatchModulusLength(int keyBits)
    {
        var pubArea = WithUInt16(Convert.FromHexString(RsaPubAreaHex), RsaKeyBitsOffset, (ushort) keyBits);

        AssertFails(pubArea);
    }

    [TestCase(0)]
    [TestCase(2047)] // not a whole number of octets
    [TestCase(2049)]
    [TestCase(16392)] // greater than 16384
    public void DefaultTpmPubAreaDecoder_Fails_WhenRsaKeyBitsAreInvalid(int keyBits)
    {
        var pubArea = WithUInt16(Convert.FromHexString(RsaPubAreaHex), RsaKeyBitsOffset, (ushort) keyBits);

        AssertFails(pubArea);
    }

    [TestCase(0x7F)]
    [TestCase(0x00)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenRsaModulusMostSignificantBitIsClear(int firstByte)
    {
        var pubArea = WithByte(Convert.FromHexString(RsaPubAreaHex), RsaModulusOffset, (byte) firstByte);

        AssertFails(pubArea);
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_Fails_WhenRsaModulusIsEmpty()
    {
        var source = Convert.FromHexString(RsaPubAreaHex);
        var pubArea = WithUInt16(Remove(source, RsaModulusOffset, RsaModulusLength), RsaUniqueSizeOffset, 0);

        AssertFails(pubArea);
    }

    [TestCase(1u)]
    [TestCase(2u)]
    [TestCase(3u)]
    [TestCase(5u)]
    [TestCase(6u)]
    [TestCase(8u)] // even
    [TestCase(65536u)] // even
    public void DefaultTpmPubAreaDecoder_Fails_WhenRsaExponentIsInvalid(uint exponent)
    {
        var pubArea = WithUInt32(Convert.FromHexString(RsaPubAreaHex), RsaExponentOffset, exponent);

        AssertFails(pubArea);
    }

    [TestCase(65537u, 65537u)]
    [TestCase(7u, 7u)]
    [TestCase(0u, 65537u)] // zero means the default exponent
    public void DefaultTpmPubAreaDecoder_DecodesRsaExponent_WhenRsaExponentIsValid(uint wireExponent, uint expectedExponent)
    {
        var pubArea = WithUInt32(Convert.FromHexString(RsaPubAreaHex), RsaExponentOffset, wireExponent);

        var decoded = DecodeSuccessfully(pubArea);

        Assert.That(decoded.Parameters, Is.InstanceOf<RsaParms>());
        Assert.That(((RsaParms) decoded.Parameters).Exponent, Is.EqualTo(expectedExponent));
    }

    [TestCase(RsaObjectAttributes | RestrictedBit)] // sign | decrypt | restricted
    [TestCase((RsaObjectAttributes & ~SignBit) | RestrictedBit)] // decrypt | restricted (a Storage Key)
    public void DefaultTpmPubAreaDecoder_Fails_WhenRsaKeyIsRestrictedDecryptionKey(uint attributes)
    {
        var pubArea = WithUInt32(Convert.FromHexString(RsaPubAreaHex), ObjectAttributesOffset, attributes);

        AssertFails(pubArea);
    }

    [TestCase(TpmAlgRsassa)]
    [TestCase(TpmAlgRsapss)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenRsaSignAndDecryptKeyHasNonNullScheme(int scheme)
    {
        // when both sign and decrypt are SET, the scheme shall be TPM_ALG_NULL
        var pubArea = InsertUInt16(WithUInt16(Convert.FromHexString(RsaPubAreaHex), SchemeOffset, (ushort) scheme), SchemeDetailsOffset, TpmAlgSha256);

        AssertFails(pubArea);
    }

    [TestCase(TpmAlgRsassa)]
    [TestCase(TpmAlgRsapss)]
    public void DefaultTpmPubAreaDecoder_Succeeds_WhenRsaSignOnlyKeyHasSigningScheme(int scheme)
    {
        var source = WithUInt32(Convert.FromHexString(RsaPubAreaHex), ObjectAttributesOffset, RsaObjectAttributes & ~DecryptBit);
        var pubArea = InsertUInt16(WithUInt16(source, SchemeOffset, (ushort) scheme), SchemeDetailsOffset, TpmAlgSha256);

        var decoded = DecodeSuccessfully(pubArea);

        Assert.That(decoded.ObjectAttributes & ObjectAttributes.Decrypt, Is.EqualTo((ObjectAttributes) 0));
        Assert.That(decoded.Parameters, Is.InstanceOf<RsaParms>());
        Assert.That(((RsaParms) decoded.Parameters).KeyBits, Is.EqualTo(2048));
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_Succeeds_WhenRsaSignOnlyKeyHasNullScheme()
    {
        var pubArea = WithUInt32(Convert.FromHexString(RsaPubAreaHex), ObjectAttributesOffset, RsaObjectAttributes & ~DecryptBit);

        var decoded = DecodeSuccessfully(pubArea);

        Assert.That(decoded.Type, Is.EqualTo(TpmAlgPublic.Rsa));
    }

    [TestCase(TpmAlgNull)]
    [TestCase(0x0003)] // TPM_ALG_TDES, not a hash
    [TestCase(0xFFFF)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenRsaSchemeHashAlgIsNullOrUnknown(int hashAlg)
    {
        var source = WithUInt32(Convert.FromHexString(RsaPubAreaHex), ObjectAttributesOffset, RsaObjectAttributes & ~DecryptBit);
        var pubArea = InsertUInt16(WithUInt16(source, SchemeOffset, TpmAlgRsassa), SchemeDetailsOffset, (ushort) hashAlg);

        AssertFails(pubArea);
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_Fails_WhenRsaSignOnlyKeyHasRsaesScheme()
    {
        // TPM_ALG_RSAES has no details (TPMS_EMPTY) but is a decryption scheme
        var source = WithUInt32(Convert.FromHexString(RsaPubAreaHex), ObjectAttributesOffset, RsaObjectAttributes & ~DecryptBit);
        var pubArea = WithUInt16(source, SchemeOffset, TpmAlgRsaes);

        AssertFails(pubArea);
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_Fails_WhenRsaSignOnlyKeyHasOaepScheme()
    {
        // TPM_ALG_OAEP carries a TPMS_SCHEME_HASH, which the decoder never reads (it rejects the decryption scheme first).
        // The details are left out on purpose: with them, the hashAlg would be misread as keyBits and the keyBits rule would reject the input instead of the scheme rule.
        var source = WithUInt32(Convert.FromHexString(RsaPubAreaHex), ObjectAttributesOffset, RsaObjectAttributes & ~DecryptBit);
        var pubArea = WithUInt16(source, SchemeOffset, TpmAlgOaep);

        AssertFails(pubArea);
    }

    [TestCase(0x0001)]
    [TestCase(TpmAlgEcdsa)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenRsaSchemeIsUnknown(int scheme)
    {
        var pubArea = WithUInt16(Convert.FromHexString(RsaPubAreaHex), SchemeOffset, (ushort) scheme);

        AssertFails(pubArea);
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_Fails_WhenRsaRestrictedSigningKeyHasNullScheme()
    {
        var pubArea = WithUInt32(Convert.FromHexString(RsaPubAreaHex), ObjectAttributesOffset, (RsaObjectAttributes & ~DecryptBit) | RestrictedBit);

        AssertFails(pubArea);
    }

    [TestCase(TpmAlgRsassa)]
    [TestCase(TpmAlgRsapss)]
    public void DefaultTpmPubAreaDecoder_Succeeds_WhenRsaRestrictedSigningKeyHasSigningScheme(int scheme)
    {
        var source = WithUInt32(Convert.FromHexString(RsaPubAreaHex), ObjectAttributesOffset, (RsaObjectAttributes & ~DecryptBit) | RestrictedBit);
        var pubArea = InsertUInt16(WithUInt16(source, SchemeOffset, (ushort) scheme), SchemeDetailsOffset, TpmAlgSha256);

        var decoded = DecodeSuccessfully(pubArea);

        Assert.That(decoded.ObjectAttributes & ObjectAttributes.Restricted, Is.EqualTo(ObjectAttributes.Restricted));
    }

    // ---------------------------------------------------------------------------------------------
    // ECC: TPMS_ECC_PARMS and TPMS_ECC_POINT

    [Test]
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccXIsOneByteShorterThanCurveCoordinate()
    {
        // x.size = 31 with a 31-byte x: structurally consistent, only the coordinate size rule rejects it
        var source = Convert.FromHexString(EccPubAreaHex);
        var pubArea = WithUInt16(Remove(source, EccXOffset, 1), EccXSizeOffset, EccCoordinateLength - 1);

        AssertFails(pubArea);
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccYIsOneByteShorterThanCurveCoordinate()
    {
        var source = Convert.FromHexString(EccPubAreaHex);
        var pubArea = WithUInt16(Remove(source, EccYOffset, 1), EccYSizeOffset, EccCoordinateLength - 1);

        AssertFails(pubArea);
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccXIsOneByteLongerThanCurveCoordinate()
    {
        var source = Convert.FromHexString(EccPubAreaHex);
        var pubArea = WithUInt16(InsertByte(source, EccXOffset, 0x00), EccXSizeOffset, EccCoordinateLength + 1);

        AssertFails(pubArea);
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccXIsEmpty()
    {
        var source = Convert.FromHexString(EccPubAreaHex);
        var pubArea = WithUInt16(Remove(source, EccXOffset, EccCoordinateLength), EccXSizeOffset, 0);

        AssertFails(pubArea);
    }

    [TestCase(0x0004)] // TPM_ECC_NIST_P384 needs 48-byte coordinates
    [TestCase(0x0005)] // TPM_ECC_NIST_P521 needs 66-byte coordinates
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccCurveDoesNotMatchCoordinateSize(int curveId)
    {
        var pubArea = WithUInt16(Convert.FromHexString(EccPubAreaHex), EccCurveIdOffset, (ushort) curveId);

        AssertFails(pubArea);
    }

    [TestCase(0x0000)] // TPM_ECC_NONE
    [TestCase(0x0001)] // TPM_ECC_NIST_P192
    [TestCase(0x0010)] // TPM_ECC_BN_P256
    [TestCase(0x0020)] // TPM_ECC_SM2_P256
    [TestCase(0x0030)] // TPM_ECC_BP_P256_R1
    [TestCase(0x0040)] // TPM_ECC_CURVE_25519
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccCurveIsUnsupported(int curveId)
    {
        var pubArea = WithUInt16(Convert.FromHexString(EccPubAreaHex), EccCurveIdOffset, (ushort) curveId);

        AssertFails(pubArea);
    }

    [TestCase(TpmAlgMgf1)]
    [TestCase(TpmAlgKdf1Sp80056A)]
    [TestCase(TpmAlgHkdf)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccKdfIsNotNull(int kdf)
    {
        // Every non-NULL kdf carries a TPMS_SCHEME_HASH (hashAlg) as its details, which the decoder never reads (it rejects the selector first).
        // The details are left out on purpose: with them, the bytes after the selector would be misread as x.size and a later check would reject the input,
        // so the test would pass even without the "kdf shall be TPM_ALG_NULL" rule; without them, only that rule rejects it.
        var pubArea = WithUInt16(Convert.FromHexString(EccPubAreaHex), EccKdfOffset, (ushort) kdf);

        AssertFails(pubArea);
    }

    [TestCase(TpmAlgEcdh)]
    [TestCase(TpmAlgEcmqv)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccSignOnlyKeyHasKeyExchangeScheme(int scheme)
    {
        var pubArea = InsertUInt16(WithUInt16(Convert.FromHexString(EccPubAreaHex), SchemeOffset, (ushort) scheme), SchemeDetailsOffset, TpmAlgSha256);

        AssertFails(pubArea);
    }

    [TestCase(TpmAlgEcdsa)]
    [TestCase(TpmAlgEcschnorr)]
    [TestCase(TpmAlgSm2)]
    public void DefaultTpmPubAreaDecoder_Succeeds_WhenEccSignOnlyKeyHasSigningScheme(int scheme)
    {
        var pubArea = InsertUInt16(WithUInt16(Convert.FromHexString(EccPubAreaHex), SchemeOffset, (ushort) scheme), SchemeDetailsOffset, TpmAlgSha256);

        var decoded = DecodeSuccessfully(pubArea);

        Assert.That(decoded.Parameters, Is.InstanceOf<EccParms>());
        Assert.That(((EccParms) decoded.Parameters).CurveId, Is.EqualTo(TpmiEccCurve.TpmEccNistP256));
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_Succeeds_WhenEccSignOnlyKeyHasEcdaaScheme()
    {
        // TPMS_SCHEME_ECDAA: hashAlg followed by the UINT16 count
        var pubArea = InsertUInt16(InsertUInt16(WithUInt16(Convert.FromHexString(EccPubAreaHex), SchemeOffset, TpmAlgEcdaa), SchemeDetailsOffset, TpmAlgSha256), SchemeDetailsOffset + 2, 0x0001);

        var decoded = DecodeSuccessfully(pubArea);

        Assert.That(decoded.Type, Is.EqualTo(TpmAlgPublic.Ecc));
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccEcdaaSchemeIsMissingCount()
    {
        var pubArea = InsertUInt16(WithUInt16(Convert.FromHexString(EccPubAreaHex), SchemeOffset, TpmAlgEcdaa), SchemeDetailsOffset, TpmAlgSha256);

        AssertFails(pubArea);
    }

    [TestCase(TpmAlgNull)]
    [TestCase(0x0003)] // TPM_ALG_TDES, not a hash
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccSchemeHashAlgIsNullOrUnknown(int hashAlg)
    {
        var pubArea = InsertUInt16(WithUInt16(Convert.FromHexString(EccPubAreaHex), SchemeOffset, TpmAlgEcdsa), SchemeDetailsOffset, (ushort) hashAlg);

        AssertFails(pubArea);
    }

    [TestCase(TpmAlgEddsa)]
    [TestCase(TpmAlgHashEddsa)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccSchemeIsEddsa(int scheme)
    {
        // rejected regardless of the layout of the details (TPMS_EMPTY in v185, TPMS_SCHEME_HASH in the V184 reference implementation)
        var withoutDetails = WithUInt16(Convert.FromHexString(EccPubAreaHex), SchemeOffset, (ushort) scheme);
        var withHashAlg = InsertUInt16(withoutDetails, SchemeDetailsOffset, TpmAlgSha256);

        AssertFails(withoutDetails);
        AssertFails(withHashAlg);
    }

    [TestCase(TpmAlgRsassa)]
    [TestCase(0x0001)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccSchemeIsUnknown(int scheme)
    {
        var pubArea = WithUInt16(Convert.FromHexString(EccPubAreaHex), SchemeOffset, (ushort) scheme);

        AssertFails(pubArea);
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccRestrictedSigningKeyHasNullScheme()
    {
        var pubArea = WithUInt32(Convert.FromHexString(EccPubAreaHex), ObjectAttributesOffset, EccObjectAttributes | RestrictedBit);

        AssertFails(pubArea);
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_Succeeds_WhenEccRestrictedSigningKeyHasEcdsaScheme()
    {
        var source = WithUInt32(Convert.FromHexString(EccPubAreaHex), ObjectAttributesOffset, EccObjectAttributes | RestrictedBit);
        var pubArea = InsertUInt16(WithUInt16(source, SchemeOffset, TpmAlgEcdsa), SchemeDetailsOffset, TpmAlgSha256);

        var decoded = DecodeSuccessfully(pubArea);

        Assert.That(decoded.ObjectAttributes & ObjectAttributes.Restricted, Is.EqualTo(ObjectAttributes.Restricted));
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_Succeeds_WhenEccSignAndDecryptKeyHasNullScheme()
    {
        var pubArea = WithUInt32(Convert.FromHexString(EccPubAreaHex), ObjectAttributesOffset, EccObjectAttributes | DecryptBit);

        var decoded = DecodeSuccessfully(pubArea);

        Assert.That(decoded.ObjectAttributes & ObjectAttributes.Decrypt, Is.EqualTo(ObjectAttributes.Decrypt));
    }

    [TestCase(TpmAlgEcdsa)]
    [TestCase(TpmAlgSm2)]
    [TestCase(TpmAlgEcdh)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccSignAndDecryptKeyHasNonNullScheme(int scheme)
    {
        var source = WithUInt32(Convert.FromHexString(EccPubAreaHex), ObjectAttributesOffset, EccObjectAttributes | DecryptBit);
        var pubArea = InsertUInt16(WithUInt16(source, SchemeOffset, (ushort) scheme), SchemeDetailsOffset, TpmAlgSha256);

        AssertFails(pubArea);
    }

    [TestCase(EccObjectAttributes | DecryptBit | RestrictedBit)] // sign | decrypt | restricted
    [TestCase((EccObjectAttributes & ~SignBit) | DecryptBit | RestrictedBit)] // decrypt | restricted (a Storage Key)
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccKeyIsRestrictedDecryptionKey(uint attributes)
    {
        var pubArea = WithUInt32(Convert.FromHexString(EccPubAreaHex), ObjectAttributesOffset, attributes);

        AssertFails(pubArea);
    }

    [TestCase(TpmAlgEcdh)]
    [TestCase(TpmAlgNull)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccKeyIsDecryptOnly(int scheme)
    {
        // a decrypt-only ECDH key is a valid TPM key but can never sign a WebAuthn assertion
        var source = WithUInt32(Convert.FromHexString(EccPubAreaHex), ObjectAttributesOffset, (EccObjectAttributes & ~SignBit) | DecryptBit);
        var pubArea = scheme == TpmAlgNull
            ? WithUInt16(source, SchemeOffset, TpmAlgNull)
            : InsertUInt16(WithUInt16(source, SchemeOffset, (ushort) scheme), SchemeDetailsOffset, TpmAlgSha256);

        AssertFails(pubArea);
    }

    // ---------------------------------------------------------------------------------------------
    // TPMA_OBJECT combinations (PublicAttributesValidation rules that do not depend on the parent)

    [TestCase(1u << 2)] // stClear
    [TestCase(1u << 7)] // adminWithPolicy
    [TestCase(1u << 8)] // firmwareLimited (the vector is fixedTPM)
    [TestCase(1u << 9)] // svnLimited (the vector is fixedTPM)
    [TestCase(1u << 10)] // noDA
    public void DefaultTpmPubAreaDecoder_Succeeds_WhenValidObjectAttributeIsSet(uint attribute)
    {
        var pubArea = WithUInt32(Convert.FromHexString(EccPubAreaHex), ObjectAttributesOffset, EccObjectAttributes | attribute);

        var decoded = DecodeSuccessfully(pubArea);

        Assert.That((uint) decoded.ObjectAttributes & attribute, Is.EqualTo(attribute));
    }

    [TestCase(EccObjectAttributes & ~FixedParentBit)] // fixedTPM without fixedParent
    [TestCase(EccObjectAttributes | EncryptedDuplicationBit)] // fixedTPM with encryptedDuplication
    [TestCase((EccObjectAttributes & ~FixedTpmBit) | FirmwareLimitedBit)] // firmwareLimited without fixedTPM
    [TestCase((EccObjectAttributes & ~FixedTpmBit) | SvnLimitedBit)] // svnLimited without fixedTPM
    public void DefaultTpmPubAreaDecoder_Fails_WhenObjectAttributesCannotBeProducedByTpm(uint attributes)
    {
        // TPM 2.0 Part 2 v185 8.3.3.2 / 8.3.3.8 / 8.3.3.9 / 8.3.3.11; reference PublicAttributesValidation()
        var pubArea = WithUInt32(Convert.FromHexString(EccPubAreaHex), ObjectAttributesOffset, attributes);

        AssertFails(pubArea);
    }

    [TestCase(EccObjectAttributes & ~FixedTpmBit)] // fixedParent without fixedTPM: a key under a parent that is not fixedTPM
    [TestCase((EccObjectAttributes & ~FixedTpmBit & ~FixedParentBit) | EncryptedDuplicationBit)] // a duplicable key with encryptedDuplication
    public void DefaultTpmPubAreaDecoder_Succeeds_WhenObjectAttributesAreValidWithoutFixedTpm(uint attributes)
    {
        var pubArea = WithUInt32(Convert.FromHexString(EccPubAreaHex), ObjectAttributesOffset, attributes);

        var decoded = DecodeSuccessfully(pubArea);

        Assert.That(decoded.ObjectAttributes & ObjectAttributes.FixedTpm, Is.EqualTo((ObjectAttributes) 0));
    }

    [TestCase(RsaPubAreaHex)]
    [TestCase(EccPubAreaHex)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenX509SignIsSet(string pubAreaHex)
    {
        // Part 2 v185 8.3.3.15: an x509sign key may not be used by TPM2_Sign(), so it can never sign a WebAuthn assertion
        var source = Convert.FromHexString(pubAreaHex);
        var attributes = BinaryPrimitives.ReadUInt32BigEndian(source.AsSpan(ObjectAttributesOffset, 4));
        var pubArea = WithUInt32(source, ObjectAttributesOffset, attributes | X509SignBit);

        AssertFails(pubArea);
    }

    // ---------------------------------------------------------------------------------------------
    // RSA keyBits with a modulus of the matching length, so that only the keyBits rule decides

    [TestCase(512)]
    [TestCase(1016)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenRsaKeyBitsAreBelow1024(int keyBits)
    {
        AssertFails(BuildRsaPubArea((ushort) keyBits, Modulus(keyBits / 8)));
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_Fails_WhenRsaKeyBitsExceed16384()
    {
        AssertFails(BuildRsaPubArea(16392, Modulus(2049)));
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_Fails_WhenRsaKeyBitsAreNotAWholeNumberOfOctets()
    {
        // 2044 / 8 = 255 octets (integer division), so the modulus length would match without the "whole number of octets" rule
        AssertFails(BuildRsaPubArea(2044, Modulus(255)));
    }

    [TestCase(1024)]
    [TestCase(1032)]
    [TestCase(16384)]
    public void DefaultTpmPubAreaDecoder_Succeeds_WhenRsaKeyBitsAreSupported(int keyBits)
    {
        var decoded = DecodeSuccessfully(BuildRsaPubArea((ushort) keyBits, Modulus(keyBits / 8)));

        Assert.That(((RsaParms) decoded.Parameters).KeyBits, Is.EqualTo(keyBits));
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_Succeeds_WhenRsaModulusFirstByteIs0x80()
    {
        var pubArea = WithByte(Convert.FromHexString(RsaPubAreaHex), RsaModulusOffset, 0x80);

        DecodeSuccessfully(pubArea);
    }

    // ---------------------------------------------------------------------------------------------
    // ECC curves other than P-256

    [TestCase(0x0004, 48)] // TPM_ECC_NIST_P384
    [TestCase(0x0005, 66)] // TPM_ECC_NIST_P521
    public void DefaultTpmPubAreaDecoder_Succeeds_WhenEccCoordinatesHaveTheSizeOfTheCurve(int curveId, int coordinateSize)
    {
        var decoded = DecodeSuccessfully(BuildEccPubArea((ushort) curveId, Pattern(coordinateSize, 1), Pattern(coordinateSize, 2)));

        Assert.That(((EccParms) decoded.Parameters).CurveId, Is.EqualTo((TpmiEccCurve) curveId));
    }

    [TestCase(0x0004, 47)]
    [TestCase(0x0004, 49)]
    [TestCase(0x0005, 65)] // 521 bits fit into 65.125 octets: the TPM pads the coordinates to 66 octets (Part 1 v185, 44.5.3)
    [TestCase(0x0005, 67)]
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccCoordinatesDoNotHaveTheSizeOfTheCurve(int curveId, int coordinateSize)
    {
        AssertFails(BuildEccPubArea((ushort) curveId, Pattern(coordinateSize, 1), Pattern(coordinateSize, 2)));
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccYIsEmpty()
    {
        var source = Convert.FromHexString(EccPubAreaHex);
        var pubArea = WithUInt16(Remove(source, EccYOffset, EccCoordinateLength), EccYSizeOffset, 0);

        AssertFails(pubArea);
    }

    [Test]
    public void DefaultTpmPubAreaDecoder_Fails_WhenEccEcdaaSchemeEndsBeforeCount()
    {
        // TPMS_SCHEME_ECDAA: hashAlg followed by the UINT16 count - the input ends right after hashAlg
        var source = Convert.FromHexString(EccPubAreaHex);
        var pubArea = InsertUInt16(WithUInt16(source, SchemeOffset, TpmAlgEcdaa), SchemeDetailsOffset, TpmAlgSha256).AsSpan(0, SchemeDetailsOffset + 2).ToArray();

        AssertFails(pubArea);
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers

    private static byte[] WithEmptyAuthPolicy(byte[] pubArea)
    {
        return WithUInt16(Remove(pubArea, AuthPolicyOffset, AuthPolicyLength), AuthPolicySizeOffset, 0);
    }

    // TPMT_PUBLIC of an RSA sign-only key: nameAlg SHA-256, empty authPolicy, scheme TPM_ALG_NULL, default exponent
    private static byte[] BuildRsaPubArea(ushort keyBits, byte[] modulus)
    {
        var pubArea = new byte[2 + 2 + 4 + 2 + 2 + 2 + 2 + 4 + 2 + modulus.Length];
        BinaryPrimitives.WriteUInt16BigEndian(pubArea.AsSpan(0), 0x0001); // TPM_ALG_RSA
        BinaryPrimitives.WriteUInt16BigEndian(pubArea.AsSpan(2), TpmAlgSha256);
        BinaryPrimitives.WriteUInt32BigEndian(pubArea.AsSpan(4), RsaObjectAttributes & ~DecryptBit);
        BinaryPrimitives.WriteUInt16BigEndian(pubArea.AsSpan(8), 0); // authPolicy
        BinaryPrimitives.WriteUInt16BigEndian(pubArea.AsSpan(10), TpmAlgNull); // symmetric
        BinaryPrimitives.WriteUInt16BigEndian(pubArea.AsSpan(12), TpmAlgNull); // scheme
        BinaryPrimitives.WriteUInt16BigEndian(pubArea.AsSpan(14), keyBits);
        BinaryPrimitives.WriteUInt32BigEndian(pubArea.AsSpan(16), 0); // exponent
        BinaryPrimitives.WriteUInt16BigEndian(pubArea.AsSpan(20), (ushort) modulus.Length);
        modulus.CopyTo(pubArea.AsSpan(22));
        return pubArea;
    }

    // TPMT_PUBLIC of an ECC sign-only key: nameAlg SHA-256, empty authPolicy, scheme and kdf TPM_ALG_NULL
    private static byte[] BuildEccPubArea(ushort curveId, byte[] x, byte[] y)
    {
        var pubArea = new byte[2 + 2 + 4 + 2 + 2 + 2 + 2 + 2 + 2 + x.Length + 2 + y.Length];
        BinaryPrimitives.WriteUInt16BigEndian(pubArea.AsSpan(0), 0x0023); // TPM_ALG_ECC
        BinaryPrimitives.WriteUInt16BigEndian(pubArea.AsSpan(2), TpmAlgSha256);
        BinaryPrimitives.WriteUInt32BigEndian(pubArea.AsSpan(4), EccObjectAttributes);
        BinaryPrimitives.WriteUInt16BigEndian(pubArea.AsSpan(8), 0); // authPolicy
        BinaryPrimitives.WriteUInt16BigEndian(pubArea.AsSpan(10), TpmAlgNull); // symmetric
        BinaryPrimitives.WriteUInt16BigEndian(pubArea.AsSpan(12), TpmAlgNull); // scheme
        BinaryPrimitives.WriteUInt16BigEndian(pubArea.AsSpan(14), curveId);
        BinaryPrimitives.WriteUInt16BigEndian(pubArea.AsSpan(16), TpmAlgNull); // kdf
        BinaryPrimitives.WriteUInt16BigEndian(pubArea.AsSpan(18), (ushort) x.Length);
        x.CopyTo(pubArea.AsSpan(20));
        BinaryPrimitives.WriteUInt16BigEndian(pubArea.AsSpan(20 + x.Length), (ushort) y.Length);
        y.CopyTo(pubArea.AsSpan(22 + x.Length));
        return pubArea;
    }

    // an RSA modulus of the given length with the most significant bit SET
    private static byte[] Modulus(int length)
    {
        var modulus = Pattern(length, 3);
        modulus[0] = 0xC5;
        return modulus;
    }

    private static byte[] Pattern(int length, int seed)
    {
        var result = new byte[length];
        for (var i = 0; i < length; i++)
        {
            result[i] = (byte) (seed + i);
        }

        return result;
    }

    private PubArea DecodeSuccessfully(byte[] pubArea)
    {
        var result = Decoder.Decode(pubArea);
        Assert.That(result.HasError, Is.False, "The pubArea was expected to decode successfully");
        if (result.HasError)
        {
            throw new InvalidOperationException("The pubArea was expected to decode successfully");
        }

        return result.Ok;
    }

    private void AssertFails(byte[] pubArea)
    {
        var result = Decoder.Decode(pubArea);
        Assert.That(result.HasError, Is.True, "The pubArea was expected to be rejected");
    }

    private static byte[] WithByte(byte[] source, int offset, byte value)
    {
        var copy = source.AsSpan().ToArray();
        copy[offset] = value;
        return copy;
    }

    private static byte[] WithUInt16(byte[] source, int offset, ushort value)
    {
        var copy = source.AsSpan().ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(copy.AsSpan(offset, 2), value);
        return copy;
    }

    private static byte[] WithUInt32(byte[] source, int offset, uint value)
    {
        var copy = source.AsSpan().ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(copy.AsSpan(offset, 4), value);
        return copy;
    }

    private static byte[] InsertByte(byte[] source, int offset, byte value)
    {
        var result = new byte[source.Length + 1];
        source.AsSpan(0, offset).CopyTo(result);
        result[offset] = value;
        source.AsSpan(offset).CopyTo(result.AsSpan(offset + 1));
        return result;
    }

    private static byte[] InsertUInt16(byte[] source, int offset, ushort value)
    {
        var result = new byte[source.Length + 2];
        source.AsSpan(0, offset).CopyTo(result);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset, 2), value);
        source.AsSpan(offset).CopyTo(result.AsSpan(offset + 2));
        return result;
    }

    private static byte[] Remove(byte[] source, int offset, int count)
    {
        var result = new byte[source.Length - count];
        source.AsSpan(0, offset).CopyTo(result);
        source.AsSpan(offset + count).CopyTo(result.AsSpan(offset));
        return result;
    }
}
