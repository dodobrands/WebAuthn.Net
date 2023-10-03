using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Cryptography.Sign;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.Packed;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Models;
using WebAuthn.Net.Services.Serialization.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;
using WebAuthn.Net.Services.TimeProvider;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.Packed;

public class DefaultPackedAttestationStatementVerifier : IPackedAttestationStatementVerifier
{
    private readonly IAsn1Decoder _asn1Decoder;
    private readonly IDigitalSignatureVerifier _signatureVerifier;
    private readonly ITimeProvider _timeProvider;

    public DefaultPackedAttestationStatementVerifier(
        ITimeProvider timeProvider,
        IDigitalSignatureVerifier signatureVerifier,
        IAsn1Decoder asn1Decoder)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        ArgumentNullException.ThrowIfNull(asn1Decoder);
        _timeProvider = timeProvider;
        _signatureVerifier = signatureVerifier;
        _asn1Decoder = asn1Decoder;
    }

    public Result<AttestationStatementVerificationResult> Verify(
        PackedAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(authData);
        ArgumentNullException.ThrowIfNull(clientDataHash);
        // 1) Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // 2) If x5c is present:
        if (attStmt.X5C is not null)
        {
            var trustPath = new X509Certificate2[attStmt.X5C.Length];
            for (var i = 0; i < trustPath.Length; i++)
            {
                var x5CCert = new X509Certificate2(attStmt.X5C[i]);
                var currentDate = _timeProvider.GetPreciseUtcDateTime();
                if (currentDate < x5CCert.NotBefore || currentDate > x5CCert.NotAfter)
                {
                    return Result<AttestationStatementVerificationResult>.Fail();
                }

                trustPath[i] = x5CCert;
            }

            return VerifyPackedWithX5C(attStmt, authData, clientDataHash, trustPath);
        }

        // 3) If x5c is not present, self attestation is in use.
        return VerifyPackedWithoutX5C(attStmt, authData, clientDataHash);
    }

    private Result<AttestationStatementVerificationResult> VerifyPackedWithX5C(
        PackedAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash,
        X509Certificate2[] trustPath)
    {
        // 1) Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
        // using the attestation public key in attestnCert with the algorithm specified in alg.

        // The attestation certificate 'attestnCert' MUST be the first element in the array.
        var attestnCert = trustPath.First();
        var dataToVerify = Concat(authData.RawAuthData, clientDataHash);
        if (!_signatureVerifier.IsValidCertificateSign(attestnCert, attStmt.Alg, dataToVerify, attStmt.Sig))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 2) Verify that attestnCert meets the requirements in § 8.2.1 Packed Attestation Statement Certificate Requirements.
        // https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements
        if (!IsAttestnCertValid(attestnCert, out var aaguid))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 3) If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
        // verify that the value of this extension matches the 'aaguid' in 'authenticatorData'.
        if (aaguid.HasValue)
        {
            if (!authData.AttestedCredentialData.Aaguid.AsSpan().SequenceEqual(aaguid.Value.AsSpan()))
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }
        }

        // 4) Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys a Basic or AttCA attestation.
        // 5) If successful, return implementation-specific values
        // representing attestation type Basic, AttCA or uncertainty, and attestation trust path x5c.
        var result = new AttestationStatementVerificationResult(AttestationType.Basic, trustPath);
        return Result<AttestationStatementVerificationResult>.Success(result);
    }

    private Result<AttestationStatementVerificationResult> VerifyPackedWithoutX5C(
        PackedAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        // If x5c is not present, self attestation is in use.
        // 1) Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
        if (attStmt.Alg != authData.AttestedCredentialData.CredentialPublicKey.Alg)
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 2) Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
        // using the credential public key with alg.
        var dataToVerify = Concat(authData.RawAuthData, clientDataHash);
        if (!_signatureVerifier.IsValidCoseKeySign(authData.AttestedCredentialData.CredentialPublicKey, dataToVerify, attStmt.Sig))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 3) If successful, return implementation-specific values representing attestation type Self and an empty attestation trust path.
        var result = new AttestationStatementVerificationResult(AttestationType.Self);
        return Result<AttestationStatementVerificationResult>.Success(result);
    }

    private bool IsAttestnCertValid(X509Certificate2 attestnCert, [NotNullWhen(true)] out Optional<byte[]>? aaguid)
    {
        // https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements
        // 1 - Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).
        if (attestnCert.Version != 3)
        {
            aaguid = null;
            return false;
        }

        // 2 - Subject field MUST be set to:
        // Subject-C - ISO 3166 code specifying the country where the Authenticator vendor is incorporated (PrintableString)
        // Subject-O - Legal name of the Authenticator vendor (UTF8String)
        // Subject-OU - Literal string "Authenticator Attestation" (UTF8String)
        // Subject-CN - A UTF8String of the vendor’s choosing
        if (!IsValidSubject(attestnCert.SubjectName))
        {
            aaguid = null;
            return false;
        }

        // 3 - If the related attestation root certificate is used for multiple authenticator models,
        // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present,
        // containing the AAGUID as a 16-byte OCTET STRING. The extension MUST NOT be marked as critical.
        // Note that an X.509 Extension encodes the DER-encoding of the value in an OCTET STRING.
        // Thus, the AAGUID MUST be wrapped in two OCTET STRINGS to be valid.
        var extensions = attestnCert.Extensions;
        if (!TryGetAaguid(extensions, out aaguid))
        {
            aaguid = null;
            return false;
        }

        // 4 - The Basic Constraints extension MUST have the CA component set to false.
        if (!IsBasicExtensionsCaComponentFalse(extensions))
        {
            aaguid = null;
            return false;
        }

        // 5 - An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280] are both OPTIONAL
        // as the status of many attestation certificates is available through authenticator metadata services.
        // See, for example, the FIDO Metadata Service [FIDOMetadataService].
        return true;
    }

    private static bool IsValidSubject(X500DistinguishedName subjectName)
    {
        // Subject field MUST be set to:
        // Subject-C - ISO 3166 code specifying the country where the Authenticator vendor is incorporated (PrintableString)
        // Subject-O - Legal name of the Authenticator vendor (UTF8String)
        // Subject-OU - Literal string "Authenticator Attestation" (UTF8String)
        // Subject-CN - A UTF8String of the vendor’s choosing

        // form the string for splitting using new lines to avoid issues with commas
        var subjectString = subjectName.Decode(X500DistinguishedNameFlags.UseNewLines);
        var subjectMap = new Dictionary<string, string>(4);

        foreach (var line in subjectString.AsSpan().EnumerateLines())
        {
            var equalIndex = line.IndexOf('=');
            if (equalIndex < 0)
            {
                return false;
            }

            var leftHandSide = line[..equalIndex].ToString();
            var rightHandSide = line[(equalIndex + 1)..].ToString();
            subjectMap[leftHandSide] = rightHandSide;
        }

        // ISO 3166 code specifying the country where the Authenticator vendor is incorporated (PrintableString)
        if (!subjectMap.TryGetValue("C", out var subjectC))
        {
            return false;
        }

        if (string.IsNullOrEmpty(subjectC))
        {
            return false;
        }

        // Legal name of the Authenticator vendor (UTF8String)
        if (!subjectMap.TryGetValue("O", out var subjectO))
        {
            return false;
        }

        if (string.IsNullOrEmpty(subjectO))
        {
            return false;
        }

        // Literal string "Authenticator Attestation" (UTF8String)
        if (!subjectMap.TryGetValue("OU", out var subjectOu))
        {
            return false;
        }

        if (!string.Equals(subjectOu, "Authenticator Attestation", StringComparison.Ordinal))
        {
            return false;
        }

        // A UTF8String of the vendor’s choosing
        if (!subjectMap.TryGetValue("CN", out var subjectCn))
        {
            return false;
        }

        if (string.IsNullOrEmpty(subjectCn))
        {
            return false;
        }

        return true;
    }

    private bool TryGetAaguid(X509ExtensionCollection extensions, [NotNullWhen(true)] out Optional<byte[]>? aaguid)
    {
        ArgumentNullException.ThrowIfNull(extensions);
        // If the related attestation root certificate is used for multiple authenticator models,
        // the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present,
        // containing the AAGUID as a 16-byte OCTET STRING. The extension MUST NOT be marked as critical.
        // Note that an X.509 Extension encodes the DER-encoding of the value in an OCTET STRING.
        // Thus, the AAGUID MUST be wrapped in two OCTET STRINGS to be valid.
        var extension = extensions.FirstOrDefault(static x => x.Oid?.Value is "1.3.6.1.4.1.45724.1.1.4"); // id-fido-gen-ce-aaguid
        if (extension is not null)
        {
            if (extension.Critical)
            {
                aaguid = null;
                return false;
            }

            var decodeResult = _asn1Decoder.Decode(extension.RawData, AsnEncodingRules.BER);
            if (decodeResult.HasError)
            {
                aaguid = null;
                return false;
            }

            if (!decodeResult.Ok.HasValue)
            {
                aaguid = null;
                return false;
            }

            if (decodeResult.Ok.Value is not Asn1OctetString aaguidOctetString)
            {
                aaguid = null;
                return false;
            }

            aaguid = aaguid = Optional<byte[]>.Payload(aaguidOctetString.Value);
            return true;
        }

        aaguid = Optional<byte[]>.Empty();
        return true;
    }

    private static bool IsBasicExtensionsCaComponentFalse(X509ExtensionCollection extensions)
    {
        // The Basic Constraints extension MUST have the CA component set to false.
        var extension = extensions.FirstOrDefault(static e => e.Oid?.Value is "2.5.29.19");
        if (extension is X509BasicConstraintsExtension basicExtension)
        {
            var isCaCert = basicExtension.CertificateAuthority;
            var isCaComponentFalse = isCaCert == false;
            return isCaComponentFalse;
        }

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
