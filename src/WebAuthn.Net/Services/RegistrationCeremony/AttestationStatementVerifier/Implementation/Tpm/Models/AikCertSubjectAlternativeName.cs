using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.Tpm.Models;

public class AikCertSubjectAlternativeName
{
    private AikCertSubjectAlternativeName(string tpmManufacturer, string tpmPartNumber, string tpmFirmwareVersion)
    {
        TpmManufacturer = tpmManufacturer;
        TpmPartNumber = tpmPartNumber;
        TpmFirmwareVersion = tpmFirmwareVersion;
    }

    public string TpmManufacturer { get; }
    public string TpmPartNumber { get; }
    public string TpmFirmwareVersion { get; }

    public static bool TryGetAikCertSubjectAlternativeName(
        X509Certificate2 aikCert,
        [NotNullWhen(true)] out AikCertSubjectAlternativeName? san)
    {
        ArgumentNullException.ThrowIfNull(aikCert);
        const string tpmManufacturer = "2.23.133.2.1";
        const string tpmModel = "2.23.133.2.2";
        const string tpmVersion = "2.23.133.2.3";

        if (!TryGetSanExtension(aikCert, out var sanExtension))
        {
            san = null;
            return false;
        }

        if (!TryParseSanExtensionValues(sanExtension, out var values))
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

    private static bool TryGetSanExtension(X509Certificate2 cert, [NotNullWhen(true)] out X509Extension? sanExtension)
    {
        const string subjectAlternativeNameOid = "2.5.29.17";
        foreach (var extension in cert.Extensions)
        {
            if (extension.Oid?.Value == subjectAlternativeNameOid)
            {
                sanExtension = extension;
                return true;
            }
        }

        sanExtension = null;
        return false;
    }


    private static bool TryParseSanExtensionValues(X509Extension extension, [NotNullWhen(true)] out Dictionary<string, string>? values)
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
        var rootReader = new AsnReader(extension.RawData, AsnEncodingRules.DER);
        if (!rootReader.HasData)
        {
            values = null;
            return false;
        }

        var rootTag = rootReader.PeekTag();
        AsnReader serialNumberReader;
        // Certificate or CertificateSerialNumber?
        if (rootTag == new Asn1Tag(UniversalTagNumber.Sequence, true))
        {
            var rootSequence = rootReader.ReadSequence();
            var rootSequenceTag = rootSequence.PeekTag();
            // Certificate with nested TBSCertificate
            if (rootSequenceTag is { TagClass: TagClass.ContextSpecific, TagValue: (int) UniversalTagNumber.OctetString, IsConstructed: true })
            {
                var encodedTbsCertificate = rootSequence.ReadEncodedValue();
                var tbsCertificateRootReader = new AsnReader(encodedTbsCertificate, AsnEncodingRules.DER);
                var tbsCertificateReader = tbsCertificateRootReader.ReadSetOf(rootSequenceTag);
                // CertificateSerialNumber
                var tbsCertificateReaderTag = tbsCertificateReader.PeekTag();
                if (tbsCertificateReaderTag != new Asn1Tag(UniversalTagNumber.Sequence, true))
                {
                    values = null;
                    return false;
                }

                serialNumberReader = tbsCertificateReader.ReadSequence();
            }
            // CertificateSerialNumber
            else if (rootSequenceTag == new Asn1Tag(UniversalTagNumber.Set, true))
            {
                serialNumberReader = rootSequence;
            }
            else
            {
                values = null;
                return false;
            }
        }
        // TBSCertificate
        else if (rootTag is { TagClass: TagClass.ContextSpecific, TagValue: (int) UniversalTagNumber.OctetString, IsConstructed: true })
        {
            var encodedTbsCertificate = rootReader.ReadEncodedValue();
            var tbsCertificateRootReader = new AsnReader(encodedTbsCertificate, AsnEncodingRules.DER);
            var tbsCertificateReader = tbsCertificateRootReader.ReadSetOf(rootTag);
            // CertificateSerialNumber
            var tbsCertificateReaderTag = tbsCertificateReader.PeekTag();
            if (tbsCertificateReaderTag != new Asn1Tag(UniversalTagNumber.Sequence, true))
            {
                values = null;
                return false;
            }

            serialNumberReader = tbsCertificateReader.ReadSequence();
        }
        else
        {
            values = null;
            return false;
        }

        // CertificateSerialNumber
        if (serialNumberReader.PeekTag() != new Asn1Tag(UniversalTagNumber.Set, true))
        {
            values = null;
            return false;
        }

        // Read CertificateSerialNumber
        var accumulatedValue = new Dictionary<string, string>();
        while (serialNumberReader.HasData)
        {
            var nestedSequence = serialNumberReader.ReadSetOf();
            if (nestedSequence.PeekTag() != new Asn1Tag(UniversalTagNumber.Sequence, true))
            {
                values = null;
                return false;
            }

            var nestedSequenceReader = nestedSequence.ReadSequence();
            if (nestedSequenceReader.PeekTag() != Asn1Tag.ObjectIdentifier)
            {
                values = null;
                return false;
            }

            var objectIdentifier = nestedSequenceReader.ReadObjectIdentifier();
            if (nestedSequenceReader.PeekTag() != new Asn1Tag(UniversalTagNumber.UTF8String))
            {
                values = null;
                return false;
            }

            var value = nestedSequenceReader.ReadCharacterString(UniversalTagNumber.UTF8String);
            accumulatedValue[objectIdentifier] = value;
        }

        if (rootReader.HasData)
        {
            values = null;
            return false;
        }

        if (serialNumberReader.HasData)
        {
            values = null;
            return false;
        }

        values = accumulatedValue;
        return true;
    }
}
