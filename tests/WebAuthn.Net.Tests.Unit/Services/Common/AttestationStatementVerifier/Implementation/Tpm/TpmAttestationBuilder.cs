using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models.Enums;
using WebAuthn.Net.Services.Cryptography.Sign.Implementation;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.Serialization.Asn1.Implementation;
using WebAuthn.Net.Services.Serialization.Cose.Models;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;

/// <summary>
///     Builds a complete, valid TPM attestation statement - an AIK certificate issued by a test CA, a pubArea for a fresh credential key, a certInfo with the matching Name and extraData,
///     and the AIK signature over it - with one switch per rule of WebAuthn L3 §8.3 / §8.3.1, so that a test can break exactly one rule.
///     Everything is generated at a fixed point in time (<see cref="Now" />), so the tests do not depend on the current date.
/// </summary>
internal sealed class TpmAttestationBuilder
{
    public const string TpmManufacturerOid = "2.23.133.2.1";
    public const string TpmModelOid = "2.23.133.2.2";
    public const string TpmVersionOid = "2.23.133.2.3";
    public const string HardwareModuleNameOid = "1.3.6.1.5.5.7.8.4";
    public const string AikCertificateExtendedKeyUsage = "2.23.133.8.3";
    public const uint RsaObjectAttributes = 0x00060472; // fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | noDA | decrypt | sign (Windows Hello RSA key)
    public const uint EccObjectAttributes = 0x00040072; // fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | sign (Windows Hello ECC key)

    public static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    public static readonly Guid Aaguid = Guid.Parse("08987058-cadc-4b81-b6e1-30de50dcbe96");

    // the root certificate that the FIDO Metadata Service stand-in of TestTpmAttestationStatementVerifier lists for Aaguid by default (an "attca" entry);
    // it is none of the embedded roots, so the tests can tell the roots of the metadata from those of the manufacturer
    public static readonly byte[] MetadataRoot = CreateMetadataRoot();

    // ---------- authenticator data

    // the aaguid in the authenticator data, chosen by the client (the AIK certificate certifies it only with the id-fido-gen-ce-aaguid extension, see AaguidExtension)
    public Guid AuthenticatorDataAaguid { get; init; } = Aaguid;

    // ---------- credential key (pubArea)

    public bool RsaCredentialKey { get; init; }

    public uint RsaExponent { get; init; }

    public ushort Curve { get; init; } = 0x0003;

    public ushort NameAlg { get; init; } = 0x000B;

    public uint? ObjectAttributes { get; init; }

    public bool MismatchedCoseKey { get; init; }

    public bool OffCurveCredentialPoint { get; init; }

    // ---------- certInfo

    public ushort? NameAlgIdInCertInfo { get; init; }

    public bool CorruptNameDigest { get; init; }

    public bool EmptyNameInCertInfo { get; init; }

    public bool WrongExtraData { get; init; }

    // ---------- statement

    public bool EmptyX5C { get; init; }

    public bool CorruptSignature { get; init; }

    // alg = RS1: the RSA AIK signs certInfo with RSASSA-PKCS1-v1_5 and SHA-1, and extraData = SHA-1(attToBeSigned)
    public bool SignWithRs1 { get; init; }

    // ---------- AIK certificate

    public bool EcdsaAik { get; init; }

    public byte[]? AikSubjectPublicKeyInfo { get; init; }

    public int CertificateVersion { get; init; } = 2;

    public byte[] Subject { get; init; } = { 0x30, 0x00 };

    public DateTimeOffset NotBefore { get; init; } = Now.AddDays(-1);

    public DateTimeOffset NotAfter { get; init; } = Now.AddDays(30);

    public byte[]? SubjectAlternativeName { get; init; }

    public bool SubjectAlternativeNameCritical { get; init; } = true;

    public bool OmitSubjectAlternativeName { get; init; }

    public string TpmManufacturer { get; init; } = "id:414D4400";

    public string TpmModel { get; init; } = "AMD";

    public string TpmVersion { get; init; } = "id:00030001";

    public string[]? ExtendedKeyUsages { get; init; } = { AikCertificateExtendedKeyUsage };

    public bool DuplicateExtendedKeyUsage { get; init; }

    public bool? BasicConstraintsCa { get; init; } = false;

    public byte[]? BasicConstraintsValue { get; init; }

    public byte[]? ExtendedKeyUsageValue { get; init; }

    public Guid? AaguidExtension { get; init; }

    public bool AaguidExtensionCritical { get; init; }

    public byte[]? AaguidExtensionValue { get; init; }

    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "SHA-1 nameAlg and RS1 test cases")]
    public TpmAttestation Build()
    {
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var issuerName = new X500DistinguishedName("CN=WebAuthn.Net TPM Test AIK CA").RawData;
        using var aikRsaKey = RSA.Create(2048);
        using var aikEcdsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var aikSpki = AikSubjectPublicKeyInfo ?? (EcdsaAik ? aikEcdsaKey.ExportSubjectPublicKeyInfo() : aikRsaKey.ExportSubjectPublicKeyInfo());
        var aikCertificate = BuildCertificate(issuerKey, issuerName, CertificateVersion, Subject, aikSpki, NotBefore, NotAfter, BuildAikExtensions());

        var (pubArea, coseKey) = BuildCredentialKey();

        // authenticator data: only its raw form takes part in attToBeSigned
        var credentialId = Pattern(16, 9);
        var rpIdHash = SHA256.HashData("example.com"u8);
        var rawAuthenticatorData = rpIdHash
            .Concat(new byte[] { 0x45, 0, 0, 0, 0 })
            .Concat(AuthenticatorDataAaguid.ToByteArray(true))
            .Concat(new byte[] { 0, 16 })
            .Concat(credentialId)
            .ToArray();
        var authenticatorData = new AttestedAuthenticatorData(
            rawAuthenticatorData,
            rpIdHash,
            AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.UserVerified | AuthenticatorDataFlags.AttestedCredentialData,
            0,
            new(AuthenticatorDataAaguid, credentialId, coseKey));
        var clientDataHash = SHA256.HashData("{\"type\":\"webauthn.create\"}"u8);
        // extraData = H_alg(attToBeSigned), with the hash algorithm of 'alg' (RS256 and ES256: SHA-256, RS1: SHA-1)
        var attToBeSigned = rawAuthenticatorData.Concat(WrongExtraData ? new byte[32] : clientDataHash).ToArray();
        var extraData = SignWithRs1 ? SHA1.HashData(attToBeSigned) : SHA256.HashData(attToBeSigned);

        // certInfo (TPMS_ATTEST, Part 2 v185 Table 154)
        var nameDigest = NameAlg switch
        {
            0x0004 => SHA1.HashData(pubArea),
            0x000B => SHA256.HashData(pubArea),
            0x000C => SHA384.HashData(pubArea),
            0x000D => SHA512.HashData(pubArea),
            _ => Pattern(32, 3) // e.g. TPM_ALG_SM3_256 (32 bytes), which the library cannot compute
        };
        if (CorruptNameDigest)
        {
            nameDigest[0] ^= 0xFF;
        }

        var certInfo = new List<byte>();
        AddUInt32(certInfo, 0xFF544347); // magic: TPM_GENERATED_VALUE
        AddUInt16(certInfo, 0x8017); // type: TPM_ST_ATTEST_CERTIFY
        AddUInt16(certInfo, 34); // qualifiedSigner: SHA-256 Name
        AddUInt16(certInfo, 0x000B);
        certInfo.AddRange(Pattern(32, 7));
        AddUInt16(certInfo, extraData.Length); // extraData
        certInfo.AddRange(extraData);
        certInfo.AddRange(new byte[8]); // clockInfo.clock
        certInfo.AddRange(new byte[4]); // clockInfo.resetCount
        certInfo.AddRange(new byte[4]); // clockInfo.restartCount
        certInfo.Add(1); // clockInfo.safe
        certInfo.AddRange(new byte[8]); // firmwareVersion
        if (EmptyNameInCertInfo)
        {
            AddUInt16(certInfo, 0); // attested.certify.name: no Name
        }
        else
        {
            AddUInt16(certInfo, 2 + nameDigest.Length); // attested.certify.name
            AddUInt16(certInfo, NameAlgIdInCertInfo ?? NameAlg);
            certInfo.AddRange(nameDigest);
        }

        AddUInt16(certInfo, 34); // attested.certify.qualifiedName
        AddUInt16(certInfo, 0x000B);
        certInfo.AddRange(Pattern(32, 5));
        var certInfoBytes = certInfo.ToArray();

        var rsaAlg = SignWithRs1 ? CoseAlgorithm.RS1 : CoseAlgorithm.RS256;
        var signature = EcdsaAik
            ? aikEcdsaKey.SignData(certInfoBytes, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)
            : aikRsaKey.SignData(certInfoBytes, SignWithRs1 ? HashAlgorithmName.SHA1 : HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (CorruptSignature)
        {
            signature[10] ^= 0xFF;
        }

        var attStmt = new TpmAttestationStatement(
            "2.0",
            EcdsaAik ? CoseAlgorithm.ES256 : rsaAlg,
            EmptyX5C ? Array.Empty<byte[]>() : new[] { aikCertificate },
            signature,
            certInfoBytes,
            pubArea);
        return new(attStmt, authenticatorData, clientDataHash);
    }

    private List<(string Oid, bool Critical, byte[] Value)> BuildAikExtensions()
    {
        var extensions = new List<(string Oid, bool Critical, byte[] Value)>();
        if (BasicConstraintsValue is not null)
        {
            extensions.Add(("2.5.29.19", true, BasicConstraintsValue));
        }
        else if (BasicConstraintsCa.HasValue)
        {
            extensions.Add(("2.5.29.19", true, new X509BasicConstraintsExtension(BasicConstraintsCa.Value, false, 0, true).RawData));
        }

        if (ExtendedKeyUsageValue is not null)
        {
            extensions.Add(("2.5.29.37", false, ExtendedKeyUsageValue));
        }
        else if (ExtendedKeyUsages is not null)
        {
            var oids = new OidCollection();
            foreach (var oid in ExtendedKeyUsages)
            {
                oids.Add(new(oid));
            }

            var extendedKeyUsage = new X509EnhancedKeyUsageExtension(oids, false).RawData;
            extensions.Add(("2.5.29.37", false, extendedKeyUsage));
            if (DuplicateExtendedKeyUsage)
            {
                extensions.Add(("2.5.29.37", false, extendedKeyUsage));
            }
        }

        if (!OmitSubjectAlternativeName)
        {
            var subjectAlternativeName = SubjectAlternativeName
                                         ?? SanWithDirectoryName(Rdns(Atv(TpmManufacturerOid, TpmManufacturer), Atv(TpmModelOid, TpmModel), Atv(TpmVersionOid, TpmVersion)));
            extensions.Add(("2.5.29.17", SubjectAlternativeNameCritical, subjectAlternativeName));
        }

        if (AaguidExtensionValue is not null)
        {
            extensions.Add(("1.3.6.1.4.1.45724.1.1.4", AaguidExtensionCritical, AaguidExtensionValue));
        }
        else if (AaguidExtension.HasValue)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.WriteOctetString(AaguidExtension.Value.ToByteArray(true));
            extensions.Add(("1.3.6.1.4.1.45724.1.1.4", AaguidExtensionCritical, writer.Encode()));
        }

        return extensions;
    }

    private (byte[] PubArea, AbstractCoseKey CoseKey) BuildCredentialKey()
    {
        var pubArea = new List<byte>();
        if (RsaCredentialKey)
        {
            using var credentialKey = RSA.Create(2048);
            var parameters = credentialKey.ExportParameters(false);
            AddUInt16(pubArea, 0x0001); // type: TPM_ALG_RSA
            AddUInt16(pubArea, NameAlg);
            AddUInt32(pubArea, ObjectAttributes ?? RsaObjectAttributes);
            AddUInt16(pubArea, 0); // authPolicy: empty
            AddUInt16(pubArea, 0x0010); // symmetric: TPM_ALG_NULL
            AddUInt16(pubArea, 0x0010); // scheme: TPM_ALG_NULL
            AddUInt16(pubArea, 2048); // keyBits
            AddUInt32(pubArea, RsaExponent); // exponent (0 = 2^16 + 1)
            AddUInt16(pubArea, parameters.Modulus!.Length);
            pubArea.AddRange(parameters.Modulus);
            var coseExponent = RsaExponent == 0 ? new byte[] { 0x01, 0x00, 0x01 } : MinimalBigEndian(RsaExponent);
            return (pubArea.ToArray(), new CoseRsaKey(CoseAlgorithm.RS256, parameters.Modulus, coseExponent));
        }

        var (curve, alg, crv) = Curve switch
        {
            0x0003 => (ECCurve.NamedCurves.nistP256, CoseAlgorithm.ES256, CoseEc2EllipticCurve.P256),
            0x0004 => (ECCurve.NamedCurves.nistP384, CoseAlgorithm.ES384, CoseEc2EllipticCurve.P384),
            _ => (ECCurve.NamedCurves.nistP521, CoseAlgorithm.ES512, CoseEc2EllipticCurve.P521)
        };
        using var key = ECDsa.Create(curve);
        var point = key.ExportParameters(false).Q;
        var x = point.X!;
        var y = point.Y!.ToArray();
        if (OffCurveCredentialPoint)
        {
            y[^1] ^= 0x01;
        }

        AddUInt16(pubArea, 0x0023); // type: TPM_ALG_ECC
        AddUInt16(pubArea, NameAlg);
        AddUInt32(pubArea, ObjectAttributes ?? EccObjectAttributes);
        AddUInt16(pubArea, 0); // authPolicy: empty
        AddUInt16(pubArea, 0x0010); // symmetric: TPM_ALG_NULL
        AddUInt16(pubArea, 0x0010); // scheme: TPM_ALG_NULL
        AddUInt16(pubArea, Curve);
        AddUInt16(pubArea, 0x0010); // kdf: TPM_ALG_NULL
        AddUInt16(pubArea, x.Length);
        pubArea.AddRange(x);
        AddUInt16(pubArea, y.Length);
        pubArea.AddRange(y);
        if (MismatchedCoseKey)
        {
            using var otherKey = ECDsa.Create(curve);
            var otherPoint = otherKey.ExportParameters(false).Q;
            return (pubArea.ToArray(), new CoseEc2Key(alg, crv, otherPoint.X!, otherPoint.Y!));
        }

        return (pubArea.ToArray(), new CoseEc2Key(alg, crv, x, y));
    }

    // ---------- Subject Alternative Name helpers (RFC 5280 §4.2.1.6, EK Credential Profile 2.7 §3.1.2 / §3.2.9)

    public static byte[] Atv(string oid, string value, UniversalTagNumber stringType = UniversalTagNumber.UTF8String)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(oid);
            writer.WriteCharacterString(stringType, value);
        }

        return writer.Encode();
    }

    // RDNSequence with one single-valued RDN per AttributeTypeAndValue
    public static byte[] Rdns(params byte[][] attributeTypeAndValues)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            foreach (var attributeTypeAndValue in attributeTypeAndValues)
            {
                using (writer.PushSetOf())
                {
                    writer.WriteEncodedValue(attributeTypeAndValue);
                }
            }
        }

        return writer.Encode();
    }

    // GeneralNames { directoryName [4] { Name } } preceded and followed by optional other GeneralNames (already encoded)
    public static byte[] SanWithDirectoryName(byte[] rdnSequence, byte[][]? before = null, byte[][]? after = null)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            foreach (var generalName in before ?? Array.Empty<byte[]>())
            {
                writer.WriteEncodedValue(generalName);
            }

            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4, true)))
            {
                writer.WriteEncodedValue(rdnSequence);
            }

            foreach (var generalName in after ?? Array.Empty<byte[]>())
            {
                writer.WriteEncodedValue(generalName);
            }
        }

        return writer.Encode();
    }

    // otherName [0] { type-id 1.3.6.1.5.5.7.8.4, value [0] EXPLICIT HardwareModuleName { hwType, hwSerialNum } } (RFC 4108)
    public static byte[] HardwareModuleNameOtherName()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
        {
            writer.WriteObjectIdentifier(HardwareModuleNameOid);
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier("2.23.133.1.2");
                    writer.WriteOctetString(new byte[] { 0x01, 0x02, 0x03, 0x04 });
                }
            }
        }

        return writer.Encode();
    }

    // ---------- certificates

    // Encodes an X.509 certificate field by field (RFC 5280 §4.1), so that a test can produce what CertificateRequest refuses to:
    // any version, any subject public key (e.g. a point that is not on the curve), any validity encoding and duplicate extensions.
    public static byte[] BuildCertificate(
        ECDsa issuerKey,
        byte[] issuerName,
        int version,
        byte[] subject,
        byte[] subjectPublicKeyInfo,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        IReadOnlyList<(string Oid, bool Critical, byte[] Value)> extensions,
        byte[]? validityOverride = null)
    {
        ArgumentNullException.ThrowIfNull(issuerKey);
        ArgumentNullException.ThrowIfNull(extensions);
        var tbsWriter = new AsnWriter(AsnEncodingRules.DER);
        using (tbsWriter.PushSequence())
        {
            if (version != 0)
            {
                using (tbsWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                {
                    tbsWriter.WriteInteger(version);
                }
            }

            tbsWriter.WriteInteger(0x01020304);
            WriteEcdsaWithSha256(tbsWriter);
            tbsWriter.WriteEncodedValue(issuerName);
            if (validityOverride is not null)
            {
                tbsWriter.WriteEncodedValue(validityOverride);
            }
            else
            {
                using (tbsWriter.PushSequence())
                {
                    tbsWriter.WriteUtcTime(notBefore);
                    tbsWriter.WriteUtcTime(notAfter);
                }
            }

            tbsWriter.WriteEncodedValue(subject);
            tbsWriter.WriteEncodedValue(subjectPublicKeyInfo);
            if (extensions.Count > 0)
            {
                using (tbsWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3, true)))
                using (tbsWriter.PushSequence())
                {
                    foreach (var (oid, critical, value) in extensions)
                    {
                        using (tbsWriter.PushSequence())
                        {
                            tbsWriter.WriteObjectIdentifier(oid);
                            if (critical)
                            {
                                tbsWriter.WriteBoolean(true);
                            }

                            tbsWriter.WriteOctetString(value);
                        }
                    }
                }
            }
        }

        var tbs = tbsWriter.Encode();
        var signature = issuerKey.SignData(tbs, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        var certificateWriter = new AsnWriter(AsnEncodingRules.DER);
        using (certificateWriter.PushSequence())
        {
            certificateWriter.WriteEncodedValue(tbs);
            WriteEcdsaWithSha256(certificateWriter);
            certificateWriter.WriteBitString(signature);
        }

        return certificateWriter.Encode();
    }

    // SubjectPublicKeyInfo of a P-256 key whose public point is not on the curve
    public static byte[] OffCurveP256SubjectPublicKeyInfo()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var subjectPublicKeyInfo = key.ExportSubjectPublicKeyInfo();
        // the uncompressed point (04 || X || Y) is at the end of the BIT STRING; flipping the last bit of Y moves it off the curve
        subjectPublicKeyInfo[^1] ^= 0x01;
        return subjectPublicKeyInfo;
    }

    // SubjectPublicKeyInfo of a P-256 key with explicit curve parameters (SpecifiedECDomain, RFC 3279 §2.3.5) instead of the namedCurve OID
    public static byte[] ExplicitCurveP256SubjectPublicKeyInfo()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = key.ExportParameters(false);
        // NIST P-256 domain parameters (SEC 2, secp256r1) - hard-coded, because not every platform exports explicit parameters
        var curve = new ECCurve
        {
            CurveType = ECCurve.ECCurveType.PrimeShortWeierstrass,
            Prime = Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
            A = Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
            B = Convert.FromHexString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
            G = new()
            {
                X = Convert.FromHexString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
                Y = Convert.FromHexString("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")
            },
            Order = Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
            Cofactor = new byte[] { 0x01 }
        };
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
                        writer.WriteIntegerUnsigned(curve.Prime);
                    }

                    using (writer.PushSequence())
                    {
                        writer.WriteOctetString(curve.A);
                        writer.WriteOctetString(curve.B);
                    }

                    writer.WriteOctetString(new byte[] { 0x04 }.Concat(curve.G.X!).Concat(curve.G.Y!).ToArray());
                    writer.WriteIntegerUnsigned(curve.Order);
                    writer.WriteIntegerUnsigned(curve.Cofactor);
                }
            }

            writer.WriteBitString(new byte[] { 0x04 }.Concat(parameters.Q.X!).Concat(parameters.Q.Y!).ToArray());
        }

        return writer.Encode();
    }

    private static void WriteEcdsaWithSha256(AsnWriter writer)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier("1.2.840.10045.4.3.2");
        }
    }

    // ---------- bytes

    private static byte[] CreateMetadataRoot()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=WebAuthn.Net TPM Test Metadata Root", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var certificate = request.CreateSelfSigned(Now.AddYears(-1), Now.AddYears(10));
        return certificate.RawData;
    }

    public static byte[] Pattern(int length, int seed)
    {
        var result = new byte[length];
        for (var i = 0; i < length; i++)
        {
            result[i] = (byte) (seed + i);
        }

        return result;
    }

    private static void AddUInt16(List<byte> buffer, int value)
    {
        buffer.Add((byte) (value >> 8));
        buffer.Add((byte) value);
    }

    private static void AddUInt32(List<byte> buffer, uint value)
    {
        buffer.Add((byte) (value >> 24));
        buffer.Add((byte) (value >> 16));
        buffer.Add((byte) (value >> 8));
        buffer.Add((byte) value);
    }

    private static byte[] MinimalBigEndian(uint value)
    {
        var buffer = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        var leadingZeros = 0;
        while (leadingZeros < 3 && buffer[leadingZeros] == 0)
        {
            leadingZeros++;
        }

        return buffer[leadingZeros..];
    }
}

internal sealed record TpmAttestation(TpmAttestationStatement AttStmt, AttestedAuthenticatorData AuthenticatorData, byte[] ClientDataHash);

/// <summary>
///     <see cref="DefaultTpmAttestationStatementVerifier{TContext}" /> with the default decoders, a fixed clock, recording counters and logger,
///     the default manufacturer verifier unless another one is given, and a FIDO Metadata Service stand-in that answers only what it is given
///     (by default an "attca" entry for <see cref="TpmAttestationBuilder.Aaguid" /> that lists <see cref="TpmAttestationBuilder.MetadataRoot" />, and nothing for any other aaguid).
/// </summary>
internal sealed class TestTpmAttestationStatementVerifier : DefaultTpmAttestationStatementVerifier<FakeWebAuthnContext>
{
    public TestTpmAttestationStatementVerifier()
        : this(new FakeTimeProvider(TpmAttestationBuilder.Now), new DefaultTpmManufacturerVerifier(), DefaultFidoMetadataSearchService(), new FakeRegistrationCeremonyCounters(), new FakeLogger<DefaultTpmAttestationStatementVerifier<FakeWebAuthnContext>>())
    {
    }

    public TestTpmAttestationStatementVerifier(DateTimeOffset now)
        : this(new FakeTimeProvider(now), new DefaultTpmManufacturerVerifier(), DefaultFidoMetadataSearchService(), new FakeRegistrationCeremonyCounters(), new FakeLogger<DefaultTpmAttestationStatementVerifier<FakeWebAuthnContext>>())
    {
    }

    public TestTpmAttestationStatementVerifier(ITpmManufacturerVerifier tpmManufacturerVerifier)
        : this(new FakeTimeProvider(TpmAttestationBuilder.Now), tpmManufacturerVerifier, DefaultFidoMetadataSearchService(), new FakeRegistrationCeremonyCounters(), new FakeLogger<DefaultTpmAttestationStatementVerifier<FakeWebAuthnContext>>())
    {
    }

    public TestTpmAttestationStatementVerifier(RecordingFidoMetadataSearchService fidoMetadataSearchService)
        : this(new FakeTimeProvider(TpmAttestationBuilder.Now), new DefaultTpmManufacturerVerifier(), fidoMetadataSearchService, new FakeRegistrationCeremonyCounters(), new FakeLogger<DefaultTpmAttestationStatementVerifier<FakeWebAuthnContext>>())
    {
    }

    public TestTpmAttestationStatementVerifier(ITpmManufacturerVerifier tpmManufacturerVerifier, RecordingFidoMetadataSearchService fidoMetadataSearchService)
        : this(new FakeTimeProvider(TpmAttestationBuilder.Now), tpmManufacturerVerifier, fidoMetadataSearchService, new FakeRegistrationCeremonyCounters(), new FakeLogger<DefaultTpmAttestationStatementVerifier<FakeWebAuthnContext>>())
    {
    }

    private TestTpmAttestationStatementVerifier(
        FakeTimeProvider timeProvider,
        ITpmManufacturerVerifier tpmManufacturerVerifier,
        RecordingFidoMetadataSearchService fidoMetadataSearchService,
        FakeRegistrationCeremonyCounters counters,
        FakeLogger<DefaultTpmAttestationStatementVerifier<FakeWebAuthnContext>> logger)
        : base(
            timeProvider,
            new DefaultTpmPubAreaDecoder(),
            new DefaultTpmCertInfoDecoder(),
            new DefaultDigitalSignatureVerifier(),
            tpmManufacturerVerifier,
            new DefaultAsn1Deserializer(NullLogger<DefaultAsn1Deserializer>.Instance),
            fidoMetadataSearchService,
            counters,
            logger)
    {
        FakeFidoMetadataSearchService = fidoMetadataSearchService;
        FakeCounters = counters;
        FakeLogger = logger;
    }

    public RecordingFidoMetadataSearchService FakeFidoMetadataSearchService { get; }

    public FakeRegistrationCeremonyCounters FakeCounters { get; }

    public FakeLogger<DefaultTpmAttestationStatementVerifier<FakeWebAuthnContext>> FakeLogger { get; }

    // the policy of IsTpmBoundCredentialKeyRequired: whether a credential key that is not bound to the TPM is rejected (null - the default of the verifier, which rejects it)
    public bool? RequireTpmBoundCredentialKey { get; init; }

    // the FIDO Metadata Service stand-in of the constructors that don't take one: an "attca" entry for the aaguid of the builder
    public static RecordingFidoMetadataSearchService DefaultFidoMetadataSearchService()
    {
        return new RecordingFidoMetadataSearchService()
            .WithAaguid(TpmAttestationBuilder.Aaguid, RecordingFidoMetadataSearchService.Metadata(TpmAttestationBuilder.MetadataRoot, AuthenticatorAttestationType.ATTESTATION_ATTCA));
    }

    public async Task<Result<VerifiedAttestationStatement>> VerifyAsync(TpmAttestation attestation)
    {
        ArgumentNullException.ThrowIfNull(attestation);
        await using var context = new FakeWebAuthnContext(null, new FakeWebAuthnContextMetrics());
        return await VerifyAsync(context, attestation.AttStmt, attestation.AuthenticatorData, attestation.ClientDataHash, CancellationToken.None);
    }

    public bool TryParseSan(byte[] extension, [NotNullWhen(true)] out Dictionary<string, string>? values)
    {
        return TryParseSanExtensionValues(extension, out values);
    }

    protected override bool IsTpmBoundCredentialKeyRequired(PubArea pubArea, AttestedAuthenticatorData authenticatorData)
    {
        return RequireTpmBoundCredentialKey ?? base.IsTpmBoundCredentialKeyRequired(pubArea, authenticatorData);
    }
}
