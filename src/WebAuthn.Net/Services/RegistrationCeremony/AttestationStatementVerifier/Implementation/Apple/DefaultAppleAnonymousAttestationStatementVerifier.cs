using System;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.EC2;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.Apple;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Models;
using WebAuthn.Net.Services.Serialization.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;
using WebAuthn.Net.Services.TimeProvider;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.Apple;

public class DefaultAppleAnonymousAttestationStatementVerifier : IAppleAnonymousAttestationStatementVerifier
{
    private readonly IAsn1Decoder _asn1Decoder;
    private readonly ITimeProvider _timeProvider;

    public DefaultAppleAnonymousAttestationStatementVerifier(ITimeProvider timeProvider, IAsn1Decoder asn1Decoder)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(asn1Decoder);
        _timeProvider = timeProvider;
        _asn1Decoder = asn1Decoder;
    }

    public Result<AttestationStatementVerificationResult> Verify(
        AppleAnonymousAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(authData);
        ArgumentNullException.ThrowIfNull(clientDataHash);
        // 1) Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        if (!TryGetCertificatesTrustPath(attStmt, out var trustPath))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        var credCert = trustPath.First();
        // 2) Concatenate authenticatorData and clientDataHash to form nonceToHash.
        var nonceToHash = Concat(authData.RawAuthData, clientDataHash);
        // 3) Perform SHA-256 hash of nonceToHash to produce nonce.
        var nonce = SHA256.HashData(nonceToHash);
        // 4) Verify that nonce equals the value of the extension with OID 1.2.840.113635.100.8.2 in credCert.
        if (!TryGetNonce(credCert, out var certificateNonce))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        if (!nonce.AsSpan().SequenceEqual(certificateNonce.AsSpan()))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 5) Verify that the credential public key equals the Subject Public Key of credCert.
        if (!IsCredentialPublicKeyEqualsSubjectPublicKeyOfCredCert(credCert, authData.AttestedCredentialData.CredentialPublicKey))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 6) If successful, return implementation-specific values representing attestation type Anonymization CA and attestation trust path x5c.
        var result = new AttestationStatementVerificationResult(AttestationType.AnonCa, trustPath);
        return Result<AttestationStatementVerificationResult>.Success(result);
    }

    private static bool IsCredentialPublicKeyEqualsSubjectPublicKeyOfCredCert(X509Certificate2 credCert, AbstractCoseKey credentialPublicKey)
    {
        switch (credentialPublicKey.Kty)
        {
            case CoseKeyType.EC2:
                {
                    if (credentialPublicKey is not CoseEc2Key cose)
                    {
                        return false;
                    }

                    var certEcdsa = credCert.GetECDsaPublicKey();
                    if (certEcdsa is null)
                    {
                        return false;
                    }

                    var certParams = certEcdsa.ExportParameters(false);
                    if (!TryToCoseCurve(certParams.Curve, out var certCurve))
                    {
                        return false;
                    }

                    var certX = certParams.Q.X;
                    var certY = certParams.Q.Y;

                    return certCurve.Value == cose.Crv
                           && certX.AsSpan().SequenceEqual(cose.X.AsSpan())
                           && certY.AsSpan().SequenceEqual(cose.Y.AsSpan());
                }
            case CoseKeyType.RSA:
                {
                    if (credentialPublicKey is not CoseRsaKey cose)
                    {
                        return false;
                    }

                    var certRsa = credCert.GetRSAPublicKey();
                    if (certRsa is null)
                    {
                        return false;
                    }

                    var certParams = certRsa.ExportParameters(false);
                    var certModulus = certParams.Modulus;
                    var certExponent = certParams.Exponent;
                    if (certModulus is null || certExponent is null)
                    {
                        return false;
                    }

                    return certModulus.AsSpan().SequenceEqual(cose.ModulusN.AsSpan())
                           && certExponent.AsSpan().SequenceEqual(cose.CoseExponentE.AsSpan());
                }
            default:
                {
                    return false;
                }
        }
    }

    private static bool TryToCoseCurve(ECCurve ecCurve, [NotNullWhen(true)] out CoseEllipticCurve? coseCurve)
    {
        if (string.IsNullOrEmpty(ecCurve.Oid.Value))
        {
            coseCurve = null;
            return false;
        }

        if (ecCurve.Oid.Value.Equals(ECCurve.NamedCurves.nistP256.Oid.Value, StringComparison.Ordinal))
        {
            coseCurve = CoseEllipticCurve.P256;
            return true;
        }

        if (ecCurve.Oid.Value.Equals(ECCurve.NamedCurves.nistP384.Oid.Value, StringComparison.Ordinal))
        {
            coseCurve = CoseEllipticCurve.P384;
            return true;
        }

        if (ecCurve.Oid.Value.Equals(ECCurve.NamedCurves.nistP521.Oid.Value, StringComparison.Ordinal))
        {
            coseCurve = CoseEllipticCurve.P521;
            return true;
        }

        coseCurve = null;
        return false;
    }

    private bool TryGetNonce(X509Certificate2 credCert, [NotNullWhen(true)] out byte[]? certificateNonce)
    {
        if (!TryGetExtensionData(credCert, out var extensionData))
        {
            certificateNonce = null;
            return false;
        }

        var decodeResult = _asn1Decoder.Decode(extensionData, AsnEncodingRules.DER);
        if (decodeResult.HasError)
        {
            certificateNonce = null;
            return false;
        }

        if (!decodeResult.Ok.HasValue)
        {
            certificateNonce = null;
            return false;
        }

        // Certificate SEQUENCE (1 elem)
        // //   tbsCertificate TBSCertificate [?] [1] (1 elem)
        // //     serialNumber CertificateSerialNumber [?] OCTET STRING (32 byte) 2A2C4080A1705F7408A8FE78D211FF68871AEE73EF59EF8EE3C4DF3915A30484
        var root = decodeResult.Ok.Value;
        if (root is not Asn1Sequence certificate)
        {
            certificateNonce = null;
            return false;
        }

        var tbsCertificateItem = certificate.Items[0];
        if (tbsCertificateItem is not Asn1RawElement rawTbsCertificateItem || rawTbsCertificateItem.Tag.TagClass != TagClass.ContextSpecific)
        {
            certificateNonce = null;
            return false;
        }

        var rawTbsCertificate = rawTbsCertificateItem.RawValue;
        var asnReader = new AsnReader(rawTbsCertificate, AsnEncodingRules.DER);
        if (!asnReader.HasData)
        {
            certificateNonce = null;
            return false;
        }

        var tbsCertificateReader = asnReader.ReadSetOf(asnReader.PeekTag());
        if (!tbsCertificateReader.HasData)
        {
            certificateNonce = null;
            return false;
        }

        var tbsCertificateResult = _asn1Decoder.Decode(tbsCertificateReader.ReadEncodedValue().ToArray(), AsnEncodingRules.DER);
        if (tbsCertificateResult.HasError)
        {
            certificateNonce = null;
            return false;
        }

        if (!tbsCertificateResult.Ok.HasValue)
        {
            certificateNonce = null;
            return false;
        }

        if (tbsCertificateResult.Ok.Value is not Asn1OctetString serialNumber)
        {
            certificateNonce = null;
            return false;
        }

        certificateNonce = serialNumber.Value;
        return true;
    }

    private bool TryGetCertificatesTrustPath(AppleAnonymousAttestationStatement attStmt, [NotNullWhen(true)] out X509Certificate2[]? trustPath)
    {
        if (attStmt.X5C.Length < 2)
        {
            trustPath = null;
            return false;
        }

        var result = new X509Certificate2[attStmt.X5C.Length];
        for (var i = 0; i < result.Length; i++)
        {
            var x5CCert = new X509Certificate2(attStmt.X5C[i]);
            var currentDate = _timeProvider.GetPreciseUtcDateTime();
            if (currentDate < x5CCert.NotBefore || currentDate > x5CCert.NotAfter)
            {
                trustPath = null;
                return false;
            }

            result[i] = x5CCert;
        }

        trustPath = result;
        return true;
    }

    private static bool TryGetExtensionData(X509Certificate2 credCert, [NotNullWhen(true)] out byte[]? extensionData)
    {
        // Verify that nonce equals the value of the extension with OID 1.2.840.113635.100.8.2 in credCert.
        foreach (var extension in credCert.Extensions)
        {
            if (extension.Oid?.Value == "1.2.840.113635.100.8.2")
            {
                extensionData = extension.RawData;
                return true;
            }
        }

        extensionData = null;
        return false;
    }

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }
}
