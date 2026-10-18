using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.Cryptography.Sign.Implementation;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataSearchService;
using WebAuthn.Net.Services.Serialization.Asn1.Implementation;
using WebAuthn.Net.Storage.FidoMetadata.Implementation;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;

public class DefaultTpmAttestationStatementVerifierTests
{
    // TCG EK Credential Profile for TPM Family 2.0, Level 0, Version 2.7, §3.1.2 "TPM Device Attributes"
    private const string TpmManufacturerOid = "2.23.133.2.1";
    private const string TpmModelOid = "2.23.133.2.2";
    private const string TpmVersionOid = "2.23.133.2.3";

    // id-on-hardwareModuleName (RFC 4108) - the legacy HardwareModuleName otherName that EK Credential Profile 2.0 allowed in the Subject Alternative Name
    private const string HardwareModuleNameOid = "1.3.6.1.5.5.7.8.4";

    // RFC 5280 §4.2.1.6 GeneralName ::= CHOICE { otherName [0] OtherName, ..., dNSName [2] IA5String, ..., directoryName [4] Name, ... }
    private static readonly Asn1Tag OtherNameTag = new(TagClass.ContextSpecific, 0);
    private static readonly Asn1Tag DnsNameTag = new(TagClass.ContextSpecific, 2);
    private static readonly Asn1Tag DirectoryNameTag = new(TagClass.ContextSpecific, 4);

    private static readonly byte[] HardwareSerialNumber = { 0x01, 0x02, 0x03, 0x04 };

    [Test]
    public void TryParseSanExtensionValues_ReturnsAllAttributes_WhenEachAttributeIsInItsOwnRdn()
    {
        // EK Credential Profile Appendix A example and the Windows Hello / AMD fTPM AIK certificates of the test vectors: three single-valued RDNs
        var extension = EncodeSubjectAltName(writer => WriteDirectoryName(
            writer,
            Rdn(Utf8(TpmManufacturerOid, "id:414D4400")),
            Rdn(Utf8(TpmModelOid, "AMD")),
            Rdn(Utf8(TpmVersionOid, "id:00030001"))));
        var verifier = new TestableTpmAttestationStatementVerifier();

        var parsed = verifier.TryParseSan(extension, out var values);

        Assert.Multiple(() =>
        {
            Assert.That(parsed, Is.True);
            Assert.That(values, Is.Not.Null);
            Assert.That(values, Has.Count.EqualTo(3));
            Assert.That(values![TpmManufacturerOid], Is.EqualTo("id:414D4400"));
            Assert.That(values[TpmModelOid], Is.EqualTo("AMD"));
            Assert.That(values[TpmVersionOid], Is.EqualTo("id:00030001"));
        });
    }

    [Test]
    public void TryParseSanExtensionValues_ReturnsAllAttributes_WhenAllAttributesAreInOneRdnInReverseOrder()
    {
        // FIDO conformance tools: one RDN holding all three attributes, encoded in the order version, model, manufacturer
        // (for these values that is also the DER sort order of the SET OF, so the DER writer reproduces the encoding of the tool)
        var extension = EncodeSubjectAltName(writer => WriteDirectoryName(
            writer,
            Rdn(Utf8(TpmVersionOid, "id:13"), Utf8(TpmModelOid, "NPCT6xx"), Utf8(TpmManufacturerOid, "id:FFFFF1D0"))));
        var verifier = new TestableTpmAttestationStatementVerifier();

        var parsed = verifier.TryParseSan(extension, out var values);

        Assert.Multiple(() =>
        {
            Assert.That(IndexOfObjectIdentifier(extension, TpmVersionOid), Is.LessThan(IndexOfObjectIdentifier(extension, TpmModelOid)));
            Assert.That(IndexOfObjectIdentifier(extension, TpmModelOid), Is.LessThan(IndexOfObjectIdentifier(extension, TpmManufacturerOid)));
            Assert.That(parsed, Is.True);
            Assert.That(values, Is.Not.Null);
            Assert.That(values, Has.Count.EqualTo(3));
            Assert.That(values![TpmManufacturerOid], Is.EqualTo("id:FFFFF1D0"));
            Assert.That(values[TpmModelOid], Is.EqualTo("NPCT6xx"));
            Assert.That(values[TpmVersionOid], Is.EqualTo("id:13"));
        });
    }

    [Test]
    public void TryParseSanExtensionValues_ReturnsAllAttributes_WhenOtherGeneralNamesSurroundDirectoryName()
    {
        var extension = EncodeSubjectAltName(writer =>
        {
            // otherName [0] OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY DEFINED BY type-id } - a legacy HardwareModuleName
            using (writer.PushSequence(OtherNameTag))
            {
                writer.WriteObjectIdentifier(HardwareModuleNameOid);
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    // HardwareModuleName ::= SEQUENCE { hwType OBJECT IDENTIFIER, hwSerialNum OCTET STRING }
                    using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier("2.23.133.1.2");
                        writer.WriteOctetString(HardwareSerialNumber);
                    }
                }
            }

            WriteDirectoryName(
                writer,
                Rdn(Utf8(TpmManufacturerOid, "id:4E544300")),
                Rdn(Utf8(TpmModelOid, "NPCT75x")),
                Rdn(Utf8(TpmVersionOid, "id:00070002")));

            // dNSName [2] IA5String
            writer.WriteCharacterString(UniversalTagNumber.IA5String, "tpm.example", DnsNameTag);
        });
        var verifier = new TestableTpmAttestationStatementVerifier();

        var parsed = verifier.TryParseSan(extension, out var values);

        Assert.Multiple(() =>
        {
            Assert.That(parsed, Is.True);
            Assert.That(values, Is.Not.Null);
            Assert.That(values, Has.Count.EqualTo(3));
            Assert.That(values![TpmManufacturerOid], Is.EqualTo("id:4E544300"));
            Assert.That(values[TpmModelOid], Is.EqualTo("NPCT75x"));
            Assert.That(values[TpmVersionOid], Is.EqualTo("id:00070002"));
        });
    }

    [Test]
    public void TryParseSanExtensionValues_IgnoresOtherAttributes_WhenRdnContainsThem()
    {
        // a serial number next to the TPM device attributes (EK Credential Profile 2.7 §3.2.6 allows it in the subject; tolerated in the SAN as well)
        var extension = EncodeSubjectAltName(writer => WriteDirectoryName(
            writer,
            Rdn(Utf8(TpmManufacturerOid, "id:53544D20"), Utf8("2.5.4.5", "0123456789")),
            Rdn(Utf8(TpmModelOid, "ST33HTPHAHD4"), Utf8(TpmVersionOid, "id:0049000D"))));
        var verifier = new TestableTpmAttestationStatementVerifier();

        var parsed = verifier.TryParseSan(extension, out var values);

        Assert.Multiple(() =>
        {
            Assert.That(parsed, Is.True);
            Assert.That(values, Is.Not.Null);
            Assert.That(values, Has.Count.EqualTo(3));
            Assert.That(values![TpmManufacturerOid], Is.EqualTo("id:53544D20"));
            Assert.That(values[TpmModelOid], Is.EqualTo("ST33HTPHAHD4"));
            Assert.That(values[TpmVersionOid], Is.EqualTo("id:0049000D"));
        });
    }

    [Test]
    public void TryParseSanExtensionValues_ReturnsTrue_WhenDuplicateAttributeHasSameValue()
    {
        var extension = EncodeSubjectAltName(writer => WriteDirectoryName(
            writer,
            Rdn(Utf8(TpmManufacturerOid, "id:414D4400")),
            Rdn(Utf8(TpmModelOid, "AMD")),
            Rdn(Utf8(TpmVersionOid, "id:00030001")),
            Rdn(Utf8(TpmModelOid, "AMD"))));
        var verifier = new TestableTpmAttestationStatementVerifier();

        var parsed = verifier.TryParseSan(extension, out var values);

        Assert.Multiple(() =>
        {
            Assert.That(parsed, Is.True);
            Assert.That(values, Is.Not.Null);
            Assert.That(values![TpmModelOid], Is.EqualTo("AMD"));
        });
    }

    [Test]
    public void TryParseSanExtensionValues_ReturnsFalse_WhenDirectoryNameIsPrimitive()
    {
        // a primitive context-specific [4] element (84 ...) cannot be an EXPLICITLY tagged Name; the old AsnReader-based parser threw AsnContentException here
        var rdnSequence = EncodeRdnSequence(
            Rdn(Utf8(TpmManufacturerOid, "id:414D4400")),
            Rdn(Utf8(TpmModelOid, "AMD")),
            Rdn(Utf8(TpmVersionOid, "id:00030001")));
        var extension = EncodeSubjectAltName(writer => writer.WriteOctetString(rdnSequence, DirectoryNameTag));
        var verifier = new TestableTpmAttestationStatementVerifier();

        var parsed = true;
        Dictionary<string, string>? values = null;
        Assert.DoesNotThrow(() => parsed = verifier.TryParseSan(extension, out values));
        Assert.Multiple(() =>
        {
            Assert.That(extension[2], Is.EqualTo(0x84));
            Assert.That(parsed, Is.False);
            Assert.That(values, Is.Null);
        });
    }

    [Test]
    public void TryParseSanExtensionValues_ReturnsFalse_WhenAttributeIsMissing()
    {
        var extension = EncodeSubjectAltName(writer => WriteDirectoryName(
            writer,
            Rdn(Utf8(TpmManufacturerOid, "id:414D4400")),
            Rdn(Utf8(TpmModelOid, "AMD"))));
        var verifier = new TestableTpmAttestationStatementVerifier();

        var parsed = verifier.TryParseSan(extension, out var values);

        Assert.Multiple(() =>
        {
            Assert.That(parsed, Is.False);
            Assert.That(values, Is.Null);
        });
    }

    [Test]
    public void TryParseSanExtensionValues_ReturnsFalse_WhenAttributeValueIsPrintableString()
    {
        // EK Credential Profile 2.7 §3.1.2: TPMManufacturer, TPMModel and TPMVersion are UTF8String
        var extension = EncodeSubjectAltName(writer => WriteDirectoryName(
            writer,
            Rdn(Utf8(TpmManufacturerOid, "id:414D4400")),
            Rdn(new SanAttribute(TpmModelOid, "AMD", UniversalTagNumber.PrintableString)),
            Rdn(Utf8(TpmVersionOid, "id:00030001"))));
        var verifier = new TestableTpmAttestationStatementVerifier();

        var parsed = verifier.TryParseSan(extension, out var values);

        Assert.Multiple(() =>
        {
            Assert.That(parsed, Is.False);
            Assert.That(values, Is.Null);
        });
    }

    [Test]
    public void TryParseSanExtensionValues_ReturnsFalse_WhenDuplicateAttributeHasDifferentValue()
    {
        var extension = EncodeSubjectAltName(writer => WriteDirectoryName(
            writer,
            Rdn(Utf8(TpmManufacturerOid, "id:414D4400")),
            Rdn(Utf8(TpmModelOid, "AMD")),
            Rdn(Utf8(TpmVersionOid, "id:00030001")),
            Rdn(Utf8(TpmManufacturerOid, "id:494E5443"))));
        var verifier = new TestableTpmAttestationStatementVerifier();

        var parsed = verifier.TryParseSan(extension, out var values);

        Assert.Multiple(() =>
        {
            Assert.That(parsed, Is.False);
            Assert.That(values, Is.Null);
        });
    }

    [Test]
    public void TryParseSanExtensionValues_ReturnsFalse_WhenExtensionIsEmpty()
    {
        var verifier = new TestableTpmAttestationStatementVerifier();

        var emptyParsed = verifier.TryParseSan(Array.Empty<byte>(), out var emptyValues);
        // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName - an empty SEQUENCE is not a valid GeneralNames
        var emptyGeneralNamesParsed = verifier.TryParseSan(EncodeSubjectAltName(static _ => { }), out var emptyGeneralNamesValues);

        Assert.Multiple(() =>
        {
            Assert.That(emptyParsed, Is.False);
            Assert.That(emptyValues, Is.Null);
            Assert.That(emptyGeneralNamesParsed, Is.False);
            Assert.That(emptyGeneralNamesValues, Is.Null);
        });
    }

    [Test]
    public void TryParseSanExtensionValues_ReturnsFalse_WhenDirectoryNameIsMissing()
    {
        var extension = EncodeSubjectAltName(writer => writer.WriteCharacterString(UniversalTagNumber.IA5String, "tpm.example", DnsNameTag));
        var verifier = new TestableTpmAttestationStatementVerifier();

        var parsed = verifier.TryParseSan(extension, out var values);

        Assert.Multiple(() =>
        {
            Assert.That(parsed, Is.False);
            Assert.That(values, Is.Null);
        });
    }

    private static byte[] EncodeSubjectAltName(Action<AsnWriter> writeGeneralNames)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        // SubjectAltName ::= GeneralNames
        // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
        using (writer.PushSequence())
        {
            writeGeneralNames(writer);
        }

        return writer.Encode();
    }

    private static void WriteDirectoryName(AsnWriter writer, params SanAttribute[][] rdns)
    {
        // directoryName [4] Name - EXPLICIT tagging, because Name is a CHOICE: a constructed [4] that wraps the RDNSequence
        using (writer.PushSequence(DirectoryNameTag))
        {
            WriteRdnSequence(writer, rdns);
        }
    }

    private static byte[] EncodeRdnSequence(params SanAttribute[][] rdns)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        WriteRdnSequence(writer, rdns);
        return writer.Encode();
    }

    private static void WriteRdnSequence(AsnWriter writer, SanAttribute[][] rdns)
    {
        // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
        using (writer.PushSequence())
        {
            foreach (var rdn in rdns)
            {
                // RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue (the DER writer sorts the elements of the SET OF)
                using (writer.PushSetOf())
                {
                    foreach (var attribute in rdn)
                    {
                        // AttributeTypeAndValue ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY DEFINED BY type }
                        using (writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier(attribute.Oid);
                            writer.WriteCharacterString(attribute.StringType, attribute.Value);
                        }
                    }
                }
            }
        }
    }

    private static int IndexOfObjectIdentifier(byte[] extension, string oid)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteObjectIdentifier(oid);
        return extension.AsSpan().IndexOf(writer.Encode());
    }

    private static SanAttribute[] Rdn(params SanAttribute[] attributes)
    {
        return attributes;
    }

    private static SanAttribute Utf8(string oid, string value)
    {
        return new(oid, value);
    }

    private sealed record SanAttribute(string Oid, string Value, UniversalTagNumber StringType = UniversalTagNumber.UTF8String);

    private sealed class TestableTpmAttestationStatementVerifier : DefaultTpmAttestationStatementVerifier<FakeWebAuthnContext>
    {
        public TestableTpmAttestationStatementVerifier() : this(new FakeTimeProvider(DateTimeOffset.UtcNow))
        {
        }

        private TestableTpmAttestationStatementVerifier(FakeTimeProvider timeProvider) : base(
            timeProvider,
            new DefaultTpmPubAreaDecoder(),
            new DefaultTpmCertInfoDecoder(),
            new DefaultDigitalSignatureVerifier(),
            new DefaultTpmManufacturerVerifier(),
            new DefaultAsn1Deserializer(NullLogger<DefaultAsn1Deserializer>.Instance),
            new DefaultFidoMetadataSearchService<FakeWebAuthnContext>(new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>(), timeProvider))
        {
        }

        public bool TryParseSan(byte[] extension, [NotNullWhen(true)] out Dictionary<string, string>? values)
        {
            return TryParseSanExtensionValues(extension, out values);
        }
    }
}
