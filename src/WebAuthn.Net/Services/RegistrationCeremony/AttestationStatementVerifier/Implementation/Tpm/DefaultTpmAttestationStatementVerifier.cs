using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.Extensions;
using WebAuthn.Net.Services.Cryptography.Sign;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.Tpm;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.Tpm.Models;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.Tpm.Models.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.Tpm.Models.Enums.Extensions;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Models;
using WebAuthn.Net.Services.Serialization.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;
using WebAuthn.Net.Services.TimeProvider;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.Tpm;

public class DefaultTpmAttestationStatementVerifier : ITpmAttestationStatementVerifier
{
    private readonly IAsn1Decoder _asn1Decoder;
    private readonly IDigitalSignatureVerifier _signatureVerifier;
    private readonly ITimeProvider _timeProvider;
    private readonly ITpmManufacturerVerifier _tpmManufacturerVerifier;

    public DefaultTpmAttestationStatementVerifier(
        ITimeProvider timeProvider,
        IDigitalSignatureVerifier signatureVerifier,
        ITpmManufacturerVerifier tpmManufacturerVerifier,
        IAsn1Decoder asn1Decoder)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        ArgumentNullException.ThrowIfNull(tpmManufacturerVerifier);
        ArgumentNullException.ThrowIfNull(asn1Decoder);
        _timeProvider = timeProvider;
        _signatureVerifier = signatureVerifier;
        _tpmManufacturerVerifier = tpmManufacturerVerifier;
        _asn1Decoder = asn1Decoder;
    }

    public Result<AttestationStatementVerificationResult> Verify(
        TpmAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(authData);
        ArgumentNullException.ThrowIfNull(clientDataHash);
        // 1 - Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // 2 - Verify that the public key specified by the parameters and unique fields of pubArea
        // is identical to the credentialPublicKey in the attestedCredentialData in authenticatorData.
        if (!PubArea.TryParse(attStmt.PubArea, out var pubArea))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        if (!PubAreaKeySameAsAttestedCredentialData(pubArea, authData.AttestedCredentialData.CredentialPublicKey))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 3 - Concatenate authenticatorData and clientDataHash to form attToBeSigned.
        var attToBeSigned = Concat(authData.RawAuthData, clientDataHash);

        // 4 - Validate that certInfo is valid
        if (!IsCertInfoValid(attStmt, authData, attToBeSigned, out var trustPath))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        var result = new AttestationStatementVerificationResult(AttestationType.AttCa, trustPath);
        return Result<AttestationStatementVerificationResult>.Success(result);
    }

    private static bool PubAreaKeySameAsAttestedCredentialData(PubArea pubArea, AbstractCoseKey authDataKey)
    {
        switch (pubArea.Type)
        {
            case TpmAlgPublic.Rsa:
                {
                    return PubAreaKeyRsaSameAsAttestedCredentialData(pubArea, authDataKey);
                }
            case TpmAlgPublic.Ecc:
                {
                    return PubAreaEccSameAsAttestedCredentialData(pubArea, authDataKey);
                }
            default:
                return false;
        }
    }

    private static bool PubAreaKeyRsaSameAsAttestedCredentialData(PubArea pubArea, AbstractCoseKey authDataKey)
    {
        if (pubArea.Unique is not RsaUnique pubAreaRsaUnique)
        {
            return false;
        }

        if (pubArea.Parameters is not RsaParms pubAreaRsaParms)
        {
            return false;
        }

        if (authDataKey is not CoseRsaKey authDataRsa)
        {
            return false;
        }

        if (!pubAreaRsaUnique.Buffer.AsSpan().SequenceEqual(authDataRsa.ModulusN.AsSpan()))
        {
            return false;
        }

        if (pubAreaRsaParms.Exponent != authDataRsa.ExponentE)
        {
            return false;
        }

        return true;
    }

    private static bool PubAreaEccSameAsAttestedCredentialData(PubArea pubArea, AbstractCoseKey authDataKey)
    {
        if (pubArea.Unique is not EccUnique pubAreaEccUnique)
        {
            return false;
        }

        if (pubArea.Parameters is not EccParms pubAreaEccParms)
        {
            return false;
        }

        if (authDataKey is not CoseEc2Key authDataEc2)
        {
            return false;
        }

        if (!pubAreaEccParms.CurveId.TryToCoseEllipticCurve(out var pubAreaCoseCurve))
        {
            return false;
        }

        if (pubAreaCoseCurve.Value != authDataEc2.Crv)
        {
            return false;
        }

        if (!pubAreaEccUnique.X.AsSpan().SequenceEqual(authDataEc2.X.AsSpan()))
        {
            return false;
        }

        if (!pubAreaEccUnique.Y.AsSpan().SequenceEqual(authDataEc2.Y.AsSpan()))
        {
            return false;
        }

        return true;
    }

    private bool IsCertInfoValid(
        TpmAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] attToBeSigned,
        [NotNullWhen(true)] out X509Certificate2[]? trustPath)
    {
        // Validate that certInfo is valid:
        // 1) Verify that magic is set to TPM_GENERATED_VALUE.
        // Handled in CertInfo.TryParse
        // 2) Verify that type is set to TPM_ST_ATTEST_CERTIFY.
        // Handled in CertInfo.TryParse
        if (!CertInfo.TryParse(attStmt.CertInfo, out var certInfo))
        {
            trustPath = null;
            return false;
        }

        // 3) Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
        if (!attStmt.Alg.TryComputeHash(attToBeSigned, out var attToBeSignedHash))
        {
            trustPath = null;
            return false;
        }

        if (!certInfo.ExtraData.AsSpan().SequenceEqual(attToBeSignedHash.AsSpan()))
        {
            trustPath = null;
            return false;
        }

        // 4) Verify that 'attested' contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2] section 10.12.3,
        // whose 'name' field contains a valid 'Name' for 'pubArea',
        // as computed using the algorithm in the nameAlg field of pubArea using the procedure specified in [TPMv2-Part1] section 16.
        if (certInfo.Attested.Name.Digest is null)
        {
            trustPath = null;
            return false;
        }

        var nameAlg = certInfo.Attested.Name.Digest.HashAlg;
        var attestedNameHash = certInfo.Attested.Name.Digest.Digest;
        if (!nameAlg.TryComputeHash(attStmt.PubArea, out var pubAreaHash))
        {
            trustPath = null;
            return false;
        }

        if (!pubAreaHash.AsSpan().SequenceEqual(attestedNameHash.AsSpan()))
        {
            trustPath = null;
            return false;
        }

        // 5) Note that the remaining fields in the "Standard Attestation Structure" [TPMv2-Part1] section 31.2,
        // i.e., qualifiedSigner, clockInfo and firmwareVersion are ignored. These fields MAY be used as an input to risk engines.

        // 6) Verify that x5c is present.
        if (attStmt.X5C.Length < 1)
        {
            trustPath = null;
            return false;
        }

        var x5C = new X509Certificate2[attStmt.X5C.Length];
        for (var i = 0; i < x5C.Length; i++)
        {
            var x5CCert = new X509Certificate2(attStmt.X5C[i]);
            var currentDate = _timeProvider.GetUtcDateTime();
            if (currentDate < x5CCert.NotBefore || currentDate > x5CCert.NotAfter)
            {
                trustPath = null;
                return false;
            }

            x5C[i] = x5CCert;
        }

        var aikCert = x5C.First();
        // 7) Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the algorithm specified in alg.
        if (!_signatureVerifier.IsValidCertificateSign(aikCert, attStmt.Alg, attStmt.CertInfo, attStmt.Sig))
        {
            trustPath = null;
            return false;
        }

        // 8) Verify that aikCert meets the requirements in §8.3.1 TPM Attestation Statement Certificate Requirements.
        if (!IsTpmAttestationStatementCertificateRequirementsSatisfied(aikCert))
        {
            trustPath = null;
            return false;
        }

        // 9) If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
        // verify that the value of this extension matches the aaguid in authenticatorData.
        if (!TryGetAaguid(aikCert.Extensions, out var aaguid))
        {
            trustPath = null;
            return false;
        }

        if (aaguid.HasValue)
        {
            if (!aaguid.Value.AsSpan().SequenceEqual(authData.AttestedCredentialData.Aaguid.AsSpan()))
            {
                trustPath = null;
                return false;
            }
        }

        // 10) If successful, return implementation-specific values representing attestation type AttCA and attestation trust path x5c.
        trustPath = x5C;
        return true;
    }

    private bool IsTpmAttestationStatementCertificateRequirementsSatisfied(X509Certificate2 aikCert)
    {
        // https://www.w3.org/TR/webauthn-3/#sctn-tpm-cert-requirements
        // 1) Version MUST be set to 3.
        if (aikCert.Version != 3)
        {
            return false;
        }

        // 2) Subject field MUST be set to empty.
        if (aikCert.SubjectName.Name.Length > 0)
        {
            return false;
        }

        // 3) The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
        // https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-V-2.5-R2_published.pdf
        if (!TryGetAikCertSubjectAlternativeName(aikCert, out var san))
        {
            return false;
        }

        if (!_tpmManufacturerVerifier.IsValid(san.TpmManufacturer))
        {
            return false;
        }

        // 4) The Extended Key Usage extension MUST contain the OID 2.23.133.8.3 ("joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)").
        if (!AikCertExtendedKeyUsageExists(aikCert.Extensions))
        {
            return false;
        }

        // 5) The Basic Constraints extension MUST have the CA component set to false.
        if (!IsBasicExtensionsCaComponentFalse(aikCert.Extensions))
        {
            return false;
        }

        // 6) An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280]
        // are both OPTIONAL as the status of many attestation certificates is available through metadata services.
        // See, for example, the FIDO Metadata Service [FIDOMetadataService].
        return true;
    }

    private bool TryGetAikCertSubjectAlternativeName(
        X509Certificate2 aikCert,
        [NotNullWhen(true)] out AikCertSubjectAlternativeName? san)
    {
        const string subjectAlternativeNameOid = "2.5.29.17";
        const string tpmManufacturer = "2.23.133.2.1";
        const string tpmModel = "2.23.133.2.2";
        const string tpmVersion = "2.23.133.2.3";
        var sanExtension = aikCert.Extensions.FirstOrDefault(x => x.Oid?.Value == subjectAlternativeNameOid);
        if (sanExtension is null)
        {
            san = null;
            return false;
        }

        if (!TryParseSanExtensionValues(sanExtension.RawData, out var values))
        {
            san = null;
            return false;
        }

        if (!values.TryGetValue(tpmManufacturer, out var manufacturer))
        {
            san = null;
            return false;
        }

        if (!values.TryGetValue(tpmModel, out var model))
        {
            san = null;
            return false;
        }

        if (!values.TryGetValue(tpmVersion, out var version))
        {
            san = null;
            return false;
        }

        san = new(manufacturer, model, version);
        return true;
    }

    private bool TryParseSanExtensionValues(byte[] extension, [NotNullWhen(true)] out Dictionary<string, string>? values)
    {
        // https://trustedcomputinggroup.org/resource/http-trustedcomputinggroup-org-wp-content-uploads-tcg-ek-credential-profile-v-2-5-r2_published-pdf/
        // 3 X.509 ASN.1 Definitions
        // This section contains the format for the EK Credential instantiated as an X.509 certificate. All fields are defined in ASN.1 and encoded using DER [19].
        // A. Certificate Examples
        // A.1 Example 1 (user device TPM, e.g. PC-Client)
        // Subject alternative name:
        // TPMManufacturer = id:54534700 (TCG)
        // TPMModel = ABCDEF123456 (part number)
        // TPMVersion = id:00010023 (firmware version)
        // // SEQUENCE
        // 30 49
        //      // SET
        //      31 16
        //          // SEQUENCE
        //          30 14
        //              // OBJECT IDENTIFER tcg-at-tpmManufacturer (2.23.133.2.1)
        //              06 05 67 81 05 02 01
        //              // UTF8 STRING id:54434700 (TCG)
        //              0C 0B 69 64 3A 35 34 34 33 34 37 30 30
        //     // SET
        //     31 17
        //         // SEQUENCE
        //         30 15
        //             // OBJECT IDENTIFER tcg-at-tpmModel (2.23.133.2.2)
        //             06 05 67 81 05 02 02
        //             // UTF8 STRING ABCDEF123456
        //             0C 0C 41 42 43 44 45 46 31 32 33 34 35 36
        //     // SET
        //     31 16
        //         // SEQUENCE
        //         30 14
        //             // OBJECT IDENTIFER tcg-at-tpmVersion (2.23.133.2.3)
        //             06 05 67 81 05 02 03
        //             // UTF8 STRING id:00010023
        //             0C 0B 69 64 3A 30 30 30 31 30 30 32 33
        // ---------------------------------------------
        // A real TPM module may return such a structure:
        // Certificate SEQUENCE (1 elem)
        //   tbsCertificate TBSCertificate [?] [4] (1 elem)
        //     serialNumber CertificateSerialNumber [?] SEQUENCE (3 elem)
        //       SET (1 elem)
        //         SEQUENCE (2 elem)
        //           OBJECT IDENTIFIER 2.23.133.2.1 tcgTpmManufacturer (TCPA/TCG Attribute)
        //           UTF8String id:414D4400
        //       SET (1 elem)
        //         SEQUENCE (2 elem)
        //           OBJECT IDENTIFIER 2.23.133.2.2 tcgTpmModel (TCPA/TCG Attribute)
        //           UTF8String AMD
        //       SET (1 elem)
        //         SEQUENCE (2 elem)
        //           OBJECT IDENTIFIER 2.23.133.2.3 tcgTpmVersion (TCPA/TCG Attribute)
        //           UTF8String id:00030001
        // ---------------------------------------------
        // sometimes something like this
        // Certificate SEQUENCE (1 elem)
        //   tbsCertificate TBSCertificate [?] [4] (1 elem)
        //     serialNumber CertificateSerialNumber [?] SEQUENCE (1 elem)
        //       SET (3 elem)
        //         SEQUENCE (2 elem)
        //           OBJECT IDENTIFIER 2.23.133.2.3 tcgTpmVersion (TCPA/TCG Attribute)
        //           UTF8String id:13
        //         SEQUENCE (2 elem)
        //           OBJECT IDENTIFIER 2.23.133.2.2 tcgTpmModel (TCPA/TCG Attribute)
        //           UTF8String NPCT6xx
        //         SEQUENCE (2 elem)
        //           OBJECT IDENTIFIER 2.23.133.2.1 tcgTpmManufacturer (TCPA/TCG Attribute)
        //           UTF8String id:FFFFF1D0
        var rootDecodeResult = _asn1Decoder.Decode(extension, AsnEncodingRules.DER);
        if (rootDecodeResult.HasError)
        {
            values = null;
            return false;
        }

        if (!rootDecodeResult.Ok.HasValue)
        {
            values = null;
            return false;
        }

        var asnRoot = rootDecodeResult.Ok.Value;
        byte[] tpmSpecSanRawSequence;
        // Certificate or serialNumber?
        if (asnRoot is AbstractAsn1Enumerable rootEnumerable)
        {
            // tbsCertificate present
            if (rootEnumerable.Items.Length == 1 && rootEnumerable.Items[0] is Asn1RawElement { Tag.TagClass: TagClass.ContextSpecific } nestedRoot)
            {
                var contextSpecificReader = new AsnReader(nestedRoot.RawValue, AsnEncodingRules.DER);
                var tpmSequenceReader = contextSpecificReader.ReadSetOf(contextSpecificReader.PeekTag());
                if (tpmSequenceReader.PeekTag() is { TagClass: TagClass.Universal, TagValue: (int) UniversalTagNumber.Sequence or (int) UniversalTagNumber.Set })
                {
                    // serialNumber extract
                    tpmSpecSanRawSequence = tpmSequenceReader.ReadEncodedValue().ToArray();
                    if (tpmSequenceReader.HasData)
                    {
                        values = null;
                        return false;
                    }
                }
                else
                {
                    values = null;
                    return false;
                }
            }
            // serialNumber extract
            else if (rootEnumerable.Tag is { TagClass: TagClass.Universal, TagValue: (int) UniversalTagNumber.Sequence or (int) UniversalTagNumber.Set })
            {
                tpmSpecSanRawSequence = extension;
            }
            else
            {
                values = null;
                return false;
            }
        }
        // tbsCertificate present
        else if (asnRoot is Asn1RawElement { Tag.TagClass: TagClass.ContextSpecific } nestedRoot)
        {
            var contextSpecificReader = new AsnReader(nestedRoot.RawValue, AsnEncodingRules.DER);
            var tpmSequenceReader = contextSpecificReader.ReadSetOf(contextSpecificReader.PeekTag());
            if (tpmSequenceReader.PeekTag() is { TagClass: TagClass.Universal, TagValue: (int) UniversalTagNumber.Sequence or (int) UniversalTagNumber.Set })
            {
                // serialNumber extract
                tpmSpecSanRawSequence = tpmSequenceReader.ReadEncodedValue().ToArray();
                if (tpmSequenceReader.HasData)
                {
                    values = null;
                    return false;
                }
            }
            else
            {
                values = null;
                return false;
            }
        }
        else
        {
            values = null;
            return false;
        }

        var sanDecodeResult = _asn1Decoder.Decode(tpmSpecSanRawSequence, AsnEncodingRules.DER);
        if (sanDecodeResult.HasError)
        {
            values = null;
            return false;
        }

        if (!sanDecodeResult.Ok.HasValue)
        {
            values = null;
            return false;
        }

        if (sanDecodeResult.Ok.Value is not AbstractAsn1Enumerable tpmSpecSanSequence)
        {
            values = null;
            return false;
        }

        // go through all enumerable elements with 1 length
        while (tpmSpecSanSequence is { Items.Length: 1 } enumerable && enumerable.Items[0] is AbstractAsn1Enumerable innerEnumerable)
        {
            tpmSpecSanSequence = innerEnumerable;
        }

        var accumulator = new Dictionary<string, string>();
        foreach (var sanElement in tpmSpecSanSequence.Items)
        {
            if (sanElement is not AbstractAsn1Enumerable sanElementEnumerable)
            {
                continue;
            }

            // go through all enumerable elements with 1 length
            var currentElement = sanElementEnumerable;
            while (currentElement is { Items.Length: 1 } enumerable && enumerable.Items[0] is AbstractAsn1Enumerable innerEnumerable)
            {
                currentElement = innerEnumerable;
            }

            if (currentElement is { Items.Length: 2 } sanSetSeq)
            {
                if (sanSetSeq.Items[0] is Asn1ObjectIdentifier normalId && sanSetSeq.Items[1] is Asn1Utf8String normalValue)
                {
                    accumulator[normalId.Value] = normalValue.Value;
                }
                else if (sanSetSeq.Items[1] is Asn1ObjectIdentifier reverseOrderId && sanSetSeq.Items[0] is Asn1Utf8String reverseOrderValue)
                {
                    accumulator[reverseOrderId.Value] = reverseOrderValue.Value;
                }
            }
        }

        values = accumulator;
        return true;
    }

    private static bool AikCertExtendedKeyUsageExists(X509ExtensionCollection extensions)
    {
        const string expectedEnhancedKeyUsage = "2.23.133.8.3";

        foreach (var extension in extensions)
        {
            if (extension.Oid?.Value is "2.5.29.37" && extension is X509EnhancedKeyUsageExtension enhancedKeyUsageExtension)
            {
                foreach (var oid in enhancedKeyUsageExtension.EnhancedKeyUsages)
                {
                    if (oid.Value == expectedEnhancedKeyUsage)
                    {
                        return true;
                    }
                }
            }
        }

        return false;
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

    private bool TryGetAaguid(X509ExtensionCollection extensions, [NotNullWhen(true)] out Optional<byte[]>? aaguid)
    {
        ArgumentNullException.ThrowIfNull(extensions);
        // If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid)
        // verify that the value of this extension matches the aaguid in authenticatorData.
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

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }
}
