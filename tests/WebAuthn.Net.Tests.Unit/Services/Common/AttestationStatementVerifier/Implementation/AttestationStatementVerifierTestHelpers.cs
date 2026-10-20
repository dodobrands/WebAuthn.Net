using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models.Enums;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService;
using WebAuthn.Net.Services.Serialization.Cose.Models;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation;

/// <summary>
///     Certificates, authenticator data and FIDO Metadata Service stand-ins shared by the tests of the Packed, FIDO U2F, Apple Anonymous and Android SafetyNet attestation statement verifiers.
/// </summary>
internal static class AttestationStatementVerifierTestHelpers
{
    /// <summary>
    ///     The fixed "current time" of the verifiers under test; every certificate created here is valid around it.
    /// </summary>
    public static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public static readonly Guid Aaguid = Guid.Parse("08987058-cadc-4b81-b6e1-30de50dcbe96");

    // ---------- certificates

    // a self-signed certificate together with its private key (so that it can issue other certificates)
    public static X509Certificate2 CreateSelfSigned(string subject, ECDsa key, bool isCa, params X509Extension[] extensions)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        if (isCa)
        {
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        }

        foreach (var extension in extensions)
        {
            request.CertificateExtensions.Add(extension);
        }

        return request.CreateSelfSigned(Now.AddDays(-1), Now.AddYears(1));
    }

    public static X509Certificate2 CreateSelfSigned(string subject, bool isCa, params X509Extension[] extensions)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return CreateSelfSigned(subject, key, isCa, extensions);
    }

    // a certificate issued by 'issuer' (which must have a private key) for the public key of 'subjectKey'
    public static X509Certificate2 Issue(X509Certificate2 issuer, string subject, ECDsa subjectKey, params X509Extension[] extensions)
    {
        return Issue(issuer, subject, subjectKey, Now.AddDays(-1), Now.AddDays(30), extensions);
    }

    public static X509Certificate2 Issue(X509Certificate2 issuer, string subject, ECDsa subjectKey, DateTimeOffset notBefore, DateTimeOffset notAfter, params X509Extension[] extensions)
    {
        var request = new CertificateRequest(subject, subjectKey, HashAlgorithmName.SHA256);
        foreach (var extension in extensions)
        {
            request.CertificateExtensions.Add(extension);
        }

        var serial = RandomNumberGenerator.GetBytes(8);
        serial[0] &= 0x7F;
        return request.Create(issuer, notBefore, notAfter, serial);
    }

    // the Basic Constraints extension of an end-entity certificate (CA = false), as required for attestation certificates
    public static X509BasicConstraintsExtension EndEntityBasicConstraints()
    {
        return new(false, false, 0, true);
    }

    // loads a certificate with the plain platform loader (bypassing X509CertificateInMemoryLoader and its extension checks), or returns null when the platform refuses the certificate
    [SuppressMessage("Security", "CA5403:Do not hard-code certificate", Justification = "The certificate is built by the test that calls this helper")]
    public static X509Certificate2? LoadWithPlatformLoader(byte[] bytes)
    {
        try
        {
#if NET8_0
            return new X509Certificate2(bytes);
#else
            return X509CertificateLoader.LoadCertificate(bytes);
#endif
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    // RFC 5280 §4.2.1.2 method (1): the 160-bit SHA-1 hash of the value of the subjectPublicKey BIT STRING - the identifier the FIDO Metadata Service publishes for an attestation certificate
    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "RFC 5280 §4.2.1.2 method (1) defines the key identifier as a SHA-1 hash; it is a lookup key, not a security hash")]
    public static byte[] Rfc5280Method1KeyIdentifier(X509Certificate2 certificate)
    {
        return SHA1.HashData(certificate.PublicKey.EncodedKeyValue.RawData);
    }

    // a certificate written directly as DER (never loaded by the platform, so that it can carry what CertificateRequest cannot express or what the platform refuses to load:
    // a SubjectPublicKeyInfo with explicit curve parameters, malformed extension values, ...), signed by 'issuerKey' with ECDSA-SHA256
    public static byte[] BuildCertificate(ECDsa issuerKey, string issuer, string subject, byte[] subjectPublicKeyInfo, IReadOnlyList<X509Extension> extensions)
    {
        var tbsWriter = new AsnWriter(AsnEncodingRules.DER);
        using (tbsWriter.PushSequence())
        {
            using (tbsWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                tbsWriter.WriteInteger(2);
            }

            tbsWriter.WriteInteger(0x01020304);
            WriteEcdsaWithSha256(tbsWriter);
            tbsWriter.WriteEncodedValue(new X500DistinguishedName(issuer).RawData);
            using (tbsWriter.PushSequence())
            {
                tbsWriter.WriteUtcTime(Now.AddDays(-1));
                tbsWriter.WriteUtcTime(Now.AddDays(30));
            }

            tbsWriter.WriteEncodedValue(new X500DistinguishedName(subject).RawData);
            tbsWriter.WriteEncodedValue(subjectPublicKeyInfo);
            if (extensions.Count > 0)
            {
                using (tbsWriter.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3, true)))
                {
                    using (tbsWriter.PushSequence())
                    {
                        foreach (var extension in extensions)
                        {
                            using (tbsWriter.PushSequence())
                            {
                                tbsWriter.WriteObjectIdentifier(extension.Oid!.Value!);
                                if (extension.Critical)
                                {
                                    tbsWriter.WriteBoolean(true);
                                }

                                tbsWriter.WriteOctetString(extension.RawData);
                            }
                        }
                    }
                }
            }
        }

        var tbs = tbsWriter.Encode();
        var signature = issuerKey.SignData(tbs, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteEncodedValue(tbs);
            WriteEcdsaWithSha256(writer);
            writer.WriteBitString(signature);
        }

        return writer.Encode();
    }

    // SubjectPublicKeyInfo with explicit P-256 parameters (RFC 3279 §2.3.5 SpecifiedECDomain) whose generator is -G: a valid generator of the same group that no named curve has,
    // so the platform cannot map the parameters back to a named curve and ECCurve.Oid of the exported parameters is null
    public static byte[] ExplicitCurveNegatedGeneratorSubjectPublicKeyInfo()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = key.ExportParameters(false);
        var prime = Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
        var gx = Convert.FromHexString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
        var gy = Convert.FromHexString("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
        var p = new BigInteger(prime, true, true);
        var y = new BigInteger(gy, true, true);
        var negY = (p - y).ToByteArray(true, true);
        var negYPadded = new byte[32];
        negY.CopyTo(negYPadded, 32 - negY.Length);
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
                        writer.WriteIntegerUnsigned(prime);
                    }

                    using (writer.PushSequence())
                    {
                        writer.WriteOctetString(Convert.FromHexString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"));
                        writer.WriteOctetString(Convert.FromHexString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"));
                    }

                    writer.WriteOctetString(new byte[] { 0x04 }.Concat(gx).Concat(negYPadded).ToArray());
                    writer.WriteIntegerUnsigned(Convert.FromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"));
                    writer.WriteIntegerUnsigned(new byte[] { 0x01 });
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
            writer.WriteObjectIdentifier("1.2.840.10045.4.3.2"); // ecdsa-with-SHA256
        }
    }

    // ---------- keys

    public static CoseEc2Key ToCoseEc2Key(ECDsa key)
    {
        var parameters = key.ExportParameters(false);
        return new(CoseAlgorithm.ES256, CoseEc2EllipticCurve.P256, parameters.Q.X!, parameters.Q.Y!);
    }

    // ---------- authenticator data

    // authenticator data with attestedCredentialData whose raw form is rpIdHash || flags || signCount || aaguid || credentialIdLength || credentialId
    // (the verifiers only hash or sign the raw form, so the credential public key is not appended to it)
    public static AttestedAuthenticatorData CreateAuthenticatorData(Guid aaguid, AbstractCoseKey credentialPublicKey)
    {
        var rpIdHash = SHA256.HashData("example.com"u8);
        var credentialId = Enumerable.Range(1, 16).Select(static x => (byte) x).ToArray();
        var raw = rpIdHash
            .Concat(new byte[] { 0x45, 0, 0, 0, 0 })
            .Concat(aaguid.ToByteArray(true))
            .Concat(new byte[] { 0, (byte) credentialId.Length })
            .Concat(credentialId)
            .ToArray();
        return new(
            raw,
            rpIdHash,
            AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.UserVerified | AuthenticatorDataFlags.AttestedCredentialData,
            0,
            new(aaguid, credentialId, credentialPublicKey));
    }

    public static byte[] CreateClientDataHash()
    {
        return SHA256.HashData("{\"type\":\"webauthn.create\"}"u8);
    }

    public static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }

    public static FakeWebAuthnContext CreateContext()
    {
        return new(null, new FakeWebAuthnContextMetrics());
    }
}

/// <summary>
///     A FIDO Metadata Service stand-in that answers from fixed entries and records every lookup.
/// </summary>
internal sealed class RecordingFidoMetadataSearchService : IFidoMetadataSearchService<FakeWebAuthnContext>
{
    private readonly Dictionary<Guid, FidoMetadataResult> _byAaguid = new();
    private readonly Dictionary<string, FidoMetadataResult> _byKeyIdentifier = new(StringComparer.OrdinalIgnoreCase);

    public List<Guid> AaguidLookups { get; } = new();

    public List<string> KeyIdentifierLookups { get; } = new();

    public RecordingFidoMetadataSearchService WithAaguid(Guid aaguid, FidoMetadataResult result)
    {
        _byAaguid[aaguid] = result;
        return this;
    }

    public RecordingFidoMetadataSearchService WithKeyIdentifier(byte[] keyIdentifier, FidoMetadataResult result)
    {
        _byKeyIdentifier[Convert.ToHexString(keyIdentifier)] = result;
        return this;
    }

    public Task<FidoMetadataResult?> FindMetadataByAaguidAsync(FakeWebAuthnContext context, Guid aaguid, CancellationToken cancellationToken)
    {
        AaguidLookups.Add(aaguid);
        return Task.FromResult(_byAaguid.GetValueOrDefault(aaguid));
    }

    public Task<FidoMetadataResult?> FindMetadataBySubjectKeyIdentifierAsync(FakeWebAuthnContext context, byte[] subjectKeyIdentifier, CancellationToken cancellationToken)
    {
        var hex = Convert.ToHexString(subjectKeyIdentifier);
        KeyIdentifierLookups.Add(hex);
        return Task.FromResult(_byKeyIdentifier.GetValueOrDefault(hex));
    }

    public static FidoMetadataResult Metadata(X509Certificate2 root, params AuthenticatorAttestationType[] attestationTypes)
    {
        return Metadata(root.RawData, attestationTypes);
    }

    public static FidoMetadataResult Metadata(byte[] root, params AuthenticatorAttestationType[] attestationTypes)
    {
        return new(new[] { root }, attestationTypes);
    }
}
