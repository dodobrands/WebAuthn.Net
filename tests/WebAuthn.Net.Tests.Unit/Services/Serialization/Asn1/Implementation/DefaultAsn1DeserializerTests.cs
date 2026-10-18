using System;
using System.Formats.Asn1;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Implementation;

public class DefaultAsn1DeserializerTests
{
    private DefaultAsn1Deserializer Deserializer { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        Deserializer = new(NullLogger<DefaultAsn1Deserializer>.Instance);
    }

    [Test]
    public void Deserialize_ConsumesContextSpecificTagZero_WhenNestedInSequence()
    {
        // GeneralNames-like structure: SEQUENCE { [0] (otherName) { OID, [0] { UTF8String } }, [4] { SEQUENCE { } } }
        // Before the fix, an element whose tag number is 0 was never consumed by the SEQUENCE reader and the loop never terminated.
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                writer.WriteObjectIdentifier("1.3.6.1.5.5.7.8.4");
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, "serial");
                }
            }

            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4)))
            {
                using (writer.PushSequence())
                {
                }
            }
        }

        var encoded = writer.Encode();

        var result = Deserializer.Deserialize(encoded, AsnEncodingRules.DER);

        Assert.That(result.HasError, Is.False);
        Assert.That(result.Ok, Is.InstanceOf<Asn1Sequence>());
        var sequence = (AbstractAsn1Enumerable) result.Ok!;
        Assert.That(sequence.Items, Has.Length.EqualTo(2));
        Assert.That(sequence.Items[0], Is.InstanceOf<Asn1RawElement>());
        Assert.That(sequence.Items[0].Tag, Is.EqualTo(new Asn1Tag(TagClass.ContextSpecific, 0, true)));
        Assert.That(sequence.Items[1].Tag, Is.EqualTo(new Asn1Tag(TagClass.ContextSpecific, 4, true)));
    }

    [Test]
    public void Deserialize_ConsumesContextSpecificTagZero_WhenNestedInSet()
    {
        // SET { [0] IMPLICIT OCTET STRING, UTF8String }
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSetOf())
        {
            writer.WriteOctetString(new byte[] { 0x01, 0x02 }, new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.WriteCharacterString(UniversalTagNumber.UTF8String, "value");
        }

        var encoded = writer.Encode();

        var result = Deserializer.Deserialize(encoded, AsnEncodingRules.DER);

        Assert.That(result.HasError, Is.False);
        Assert.That(result.Ok, Is.InstanceOf<Asn1Set>());
        var set = (AbstractAsn1Enumerable) result.Ok!;
        Assert.That(set.Items, Has.Length.EqualTo(2));
    }

    [Test]
    public void Deserialize_Fails_WhenSequenceContainsEndOfContentsOctets()
    {
        // BER: SEQUENCE (definite length 4) { EndOfContents (00 00), EndOfContents (00 00) }
        // The EndOfContents octets are not a value and are rejected instead of being skipped or spinning the reader.
        var encoded = new byte[] { 0x30, 0x04, 0x00, 0x00, 0x00, 0x00 };

        var result = Deserializer.Deserialize(encoded, AsnEncodingRules.BER);

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public void Deserialize_DecodesNestedSequenceOfSets_WhenWellFormed()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSetOf())
            {
                using (writer.PushSequence())
                {
                    writer.WriteObjectIdentifier("2.23.133.2.1");
                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, "id:414D4400");
                }
            }
        }

        var encoded = writer.Encode();

        var result = Deserializer.Deserialize(encoded, AsnEncodingRules.DER);

        Assert.That(result.HasError, Is.False);
        var sequence = (AbstractAsn1Enumerable) result.Ok!;
        Assert.That(sequence.Items, Has.Length.EqualTo(1));
        var set = (AbstractAsn1Enumerable) sequence.Items[0];
        Assert.That(set.Items, Has.Length.EqualTo(1));
        var attribute = (AbstractAsn1Enumerable) set.Items[0];
        Assert.That(attribute.Items, Has.Length.EqualTo(2));
        Assert.That(attribute.Items[0], Is.InstanceOf<Asn1ObjectIdentifier>());
        Assert.That(((Asn1ObjectIdentifier) attribute.Items[0]).Value, Is.EqualTo("2.23.133.2.1"));
        Assert.That(((Asn1Utf8String) attribute.Items[1]).Value, Is.EqualTo("id:414D4400"));
    }

    [Test]
    public void Deserialize_ReturnsNull_WhenInputIsEmpty()
    {
        var result = Deserializer.Deserialize(Array.Empty<byte>(), AsnEncodingRules.DER);

        Assert.That(result.HasError, Is.False);
        Assert.That(result.Ok, Is.Null);
    }
}
