using System;
using System.Formats.Asn1;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using WebAuthn.Net.Models;
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

        var result = DeserializeWithTimeout(encoded, AsnEncodingRules.DER);

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

        var result = DeserializeWithTimeout(encoded, AsnEncodingRules.DER);

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

        var result = DeserializeWithTimeout(encoded, AsnEncodingRules.BER);

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public void Deserialize_Fails_WhenSetContainsEndOfContentsOctets()
    {
        var encoded = new byte[] { 0x31, 0x04, 0x00, 0x00, 0x00, 0x00 };

        var result = DeserializeWithTimeout(encoded, AsnEncodingRules.BER);

        Assert.That(result.HasError, Is.True);
    }

    // the nesting depth counts every element level: 31 SEQUENCEs and the NULL inside them are 32 levels, the limit
    [TestCase(1)]
    [TestCase(31)]
    public void Deserialize_DecodesNestedSequences_WhenNestingIsWithinLimit(int sequences)
    {
        var result = Deserializer.Deserialize(NestedSequences(sequences), AsnEncodingRules.DER);

        Assert.That(result.HasError, Is.False);
    }

    [TestCase(32)]
    [TestCase(100_000)]
    public void Deserialize_Fails_WhenNestingExceedsLimit(int sequences)
    {
        // Without the limit, the recursive descent overflows the stack for a few thousand levels - which terminates the process instead of failing.
        var result = Deserializer.Deserialize(NestedSequences(sequences), AsnEncodingRules.DER);

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

    // DER SEQUENCE { SEQUENCE { ... SEQUENCE { NULL } ... } } with the given number of SEQUENCEs,
    // written from the outermost header inwards (re-encoding level by level would be quadratic for deep inputs)
    private static byte[] NestedSequences(int sequences)
    {
        var contentLengths = new int[sequences];
        var length = 2; // NULL
        for (var i = sequences - 1; i >= 0; i--)
        {
            contentLengths[i] = length;
            length += 1 + LengthOfLength(length);
        }

        var result = new byte[length];
        var offset = 0;
        for (var i = 0; i < sequences; i++)
        {
            result[offset++] = 0x30;
            offset += WriteLength(result.AsSpan(offset), contentLengths[i]);
        }

        result[offset] = 0x05;
        result[offset + 1] = 0x00;
        return result;
    }

    private static int LengthOfLength(int length)
    {
        return length switch
        {
            < 0x80 => 1,
            <= 0xFF => 2,
            <= 0xFFFF => 3,
            <= 0xFFFFFF => 4,
            _ => 5
        };
    }

    private static int WriteLength(Span<byte> destination, int length)
    {
        var size = LengthOfLength(length);
        if (size == 1)
        {
            destination[0] = (byte) length;
            return 1;
        }

        destination[0] = (byte) (0x80 | (size - 1));
        for (var i = 1; i < size; i++)
        {
            destination[i] = (byte) (length >> (8 * (size - 1 - i)));
        }

        return size;
    }

    // a regression that makes the deserializer loop forever fails the test instead of hanging the test run
    private Result<AbstractAsn1Element?> DeserializeWithTimeout(byte[] encoded, AsnEncodingRules rules)
    {
        var task = Task.Run(() => Deserializer.Deserialize(encoded, rules));
        Assert.That(task.Wait(TimeSpan.FromSeconds(10)), Is.True, "The deserializer did not finish within 10 seconds");
        return task.Result;
    }

    [Test]
    public void Deserialize_ReturnsNull_WhenInputIsEmpty()
    {
        var result = Deserializer.Deserialize(Array.Empty<byte>(), AsnEncodingRules.DER);

        Assert.That(result.HasError, Is.False);
        Assert.That(result.Ok, Is.Null);
    }
}
