using System.Collections.Generic;
using System.Formats.Asn1;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Implementation;

public class DefaultAsn1Deserializer : IAsn1Deserializer
{
    public Result<Optional<AbstractAsn1Element>> Deserialize(byte[] input, AsnEncodingRules encodingRules)
    {
        var reader = new AsnReader(input, encodingRules);
        if (!reader.HasData)
        {
            return Result<Optional<AbstractAsn1Element>>.Success(Optional<AbstractAsn1Element>.Empty());
        }

        var rootResult = Read(reader);
        if (rootResult.HasError)
        {
            return Result<Optional<AbstractAsn1Element>>.Fail();
        }

        var root = Optional<AbstractAsn1Element>.Payload(rootResult.Ok);
        return Result<Optional<AbstractAsn1Element>>.Success(root);
    }

    private static Result<AbstractAsn1Element> Read(AsnReader reader)
    {
        var tag = reader.PeekTag();
        return tag.TagClass switch
        {
            TagClass.Universal => ReadUniversal(reader, tag),
            TagClass.Application => ReadNonUniversal(reader, tag),
            TagClass.ContextSpecific => ReadNonUniversal(reader, tag),
            TagClass.Private => ReadNonUniversal(reader, tag),
            _ => ReadNonUniversal(reader, tag)
        };
    }

    private static Result<AbstractAsn1Element> ReadUniversal(AsnReader reader, Asn1Tag tag)
    {
        var tagValue = (UniversalTagNumber) tag.TagValue;
        return tagValue switch
        {
            UniversalTagNumber.EndOfContents => Result<AbstractAsn1Element>.Fail(),
            UniversalTagNumber.Boolean => Transform(ReadBoolean(reader, tag)),
            UniversalTagNumber.Integer => Transform(ReadInteger(reader, tag)),
            UniversalTagNumber.BitString => Transform(ReadBitString(reader, tag)),
            UniversalTagNumber.OctetString => Transform(ReadOctetString(reader, tag)),
            UniversalTagNumber.Null => Transform(ReadNull(reader, tag)),
            UniversalTagNumber.ObjectIdentifier => Transform(ReadObjectIdentifier(reader, tag)),
            UniversalTagNumber.ObjectDescriptor => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.External => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.Real => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.Enumerated => Transform(ReadEnumerated(reader, tag)),
            UniversalTagNumber.Embedded => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.UTF8String => Transform(ReadUtf8String(reader, tag)),
            UniversalTagNumber.RelativeObjectIdentifier => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.Time => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.Sequence => Transform(ReadSequence(reader, tag)),
            UniversalTagNumber.Set => Transform(ReadSet(reader, tag)),
            UniversalTagNumber.NumericString => Transform(ReadNumericString(reader, tag)),
            UniversalTagNumber.PrintableString => Transform(ReadPrintableString(reader, tag)),
            UniversalTagNumber.T61String => Transform(ReadT61String(reader, tag)),
            UniversalTagNumber.VideotexString => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.IA5String => Transform(ReadIa5String(reader, tag)),
            UniversalTagNumber.UtcTime => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.GeneralizedTime => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.GraphicString => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.VisibleString => Transform(ReadVisibleString(reader, tag)),
            UniversalTagNumber.GeneralString => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.UniversalString => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.UnrestrictedCharacterString => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.BMPString => Transform(ReadBmpString(reader, tag)),
            UniversalTagNumber.Date => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.TimeOfDay => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.DateTime => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.Duration => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.ObjectIdentifierIRI => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.RelativeObjectIdentifierIRI => Transform(ReadRaw(reader, tag)),
            _ => Transform(ReadRaw(reader, tag))
        };
    }

    private static Result<AbstractAsn1Element> ReadNonUniversal(AsnReader reader, Asn1Tag tag)
    {
        return Transform(ReadRaw(reader, tag));
    }

    private static Result<AbstractAsn1Element> Transform<TSource>(Result<TSource> source)
        where TSource : AbstractAsn1Element
    {
        return source.HasError
            ? Result<AbstractAsn1Element>.Fail()
            : Result<AbstractAsn1Element>.Success(source.Ok);
    }

    private static Result<Asn1Boolean> ReadBoolean(
        AsnReader reader,
        Asn1Tag tag)
    {
        var value = reader.ReadBoolean(tag);
        return Result<Asn1Boolean>.Success(new(tag, value));
    }

    private static Result<Asn1Integer> ReadInteger(
        AsnReader reader,
        Asn1Tag tag)
    {
        var value = reader.ReadInteger(tag);
        return Result<Asn1Integer>.Success(new(tag, value));
    }

    private static Result<Asn1BitString> ReadBitString(
        AsnReader reader,
        Asn1Tag tag)
    {
        var value = reader.ReadBitString(out var unusedBitCount, tag);
        return Result<Asn1BitString>.Success(new(tag, new(value, unusedBitCount)));
    }

    private static Result<Asn1OctetString> ReadOctetString(
        AsnReader reader,
        Asn1Tag tag)
    {
        var value = reader.ReadOctetString(tag);
        return Result<Asn1OctetString>.Success(new(tag, value));
    }

    private static Result<Asn1Null> ReadNull(
        AsnReader reader,
        Asn1Tag tag)
    {
        reader.ReadNull(tag);
        return Result<Asn1Null>.Success(new(tag));
    }

    private static Result<Asn1ObjectIdentifier> ReadObjectIdentifier(
        AsnReader reader,
        Asn1Tag tag)
    {
        var value = reader.ReadObjectIdentifier(tag);
        return Result<Asn1ObjectIdentifier>.Success(new(tag, value));
    }

    private static Result<Asn1RawElement> ReadRaw(
        AsnReader reader,
        Asn1Tag tag)
    {
        var value = reader.ReadEncodedValue();
        return Result<Asn1RawElement>.Success(new(tag, value.ToArray()));
    }

    private static Result<Asn1Enumerated> ReadEnumerated(
        AsnReader reader,
        Asn1Tag tag)
    {
        var value = reader.ReadEnumeratedBytes();
        return Result<Asn1Enumerated>.Success(new(tag, value.ToArray()));
    }

    private static Result<Asn1Utf8String> ReadUtf8String(
        AsnReader reader,
        Asn1Tag tag)
    {
        var value = reader.ReadCharacterString(UniversalTagNumber.UTF8String, tag);
        return Result<Asn1Utf8String>.Success(new(tag, value));
    }

    private static Result<Asn1Sequence> ReadSequence(
        AsnReader reader,
        Asn1Tag tag)
    {
        var sequenceItems = new List<AbstractAsn1Element>();
        var sequenceReader = reader.ReadSequence(tag);
        while (sequenceReader.HasData)
        {
            if (sequenceReader.PeekTag().TagValue != (int) UniversalTagNumber.EndOfContents)
            {
                var innerObject = Read(sequenceReader);
                if (innerObject.HasError)
                {
                    return Result<Asn1Sequence>.Fail();
                }

                sequenceItems.Add(innerObject.Ok);
            }
        }

        return Result<Asn1Sequence>.Success(new(tag, sequenceItems.ToArray()));
    }

    private static Result<Asn1Set> ReadSet(
        AsnReader reader,
        Asn1Tag tag)
    {
        var setItems = new List<AbstractAsn1Element>();
        var setReader = reader.ReadSetOf(tag);
        while (setReader.HasData)
        {
            if (setReader.PeekTag().TagValue != (int) UniversalTagNumber.EndOfContents)
            {
                var innerObject = Read(setReader);
                if (innerObject.HasError)
                {
                    return Result<Asn1Set>.Fail();
                }

                setItems.Add(innerObject.Ok);
            }
        }

        return Result<Asn1Set>.Success(new(tag, setItems.ToArray()));
    }

    private static Result<Asn1NumericString> ReadNumericString(
        AsnReader reader,
        Asn1Tag tag)
    {
        var value = reader.ReadCharacterString(UniversalTagNumber.NumericString, tag);
        return Result<Asn1NumericString>.Success(new(tag, value));
    }

    private static Result<Asn1PrintableString> ReadPrintableString(
        AsnReader reader,
        Asn1Tag tag)
    {
        var value = reader.ReadCharacterString(UniversalTagNumber.PrintableString, tag);
        return Result<Asn1PrintableString>.Success(new(tag, value));
    }

    private static Result<Asn1T61String> ReadT61String(
        AsnReader reader,
        Asn1Tag tag)
    {
        var value = reader.ReadCharacterString(UniversalTagNumber.T61String, tag);
        return Result<Asn1T61String>.Success(new(tag, value));
    }

    private static Result<Asn1Ia5String> ReadIa5String(
        AsnReader reader,
        Asn1Tag tag)
    {
        var value = reader.ReadCharacterString(UniversalTagNumber.IA5String, tag);
        return Result<Asn1Ia5String>.Success(new(tag, value));
    }

    private static Result<Asn1VisibleString> ReadVisibleString(
        AsnReader reader,
        Asn1Tag tag)
    {
        var value = reader.ReadCharacterString(UniversalTagNumber.VisibleString, tag);
        return Result<Asn1VisibleString>.Success(new(tag, value));
    }

    private static Result<Asn1BmpString> ReadBmpString(
        AsnReader reader,
        Asn1Tag tag)
    {
        var value = reader.ReadCharacterString(UniversalTagNumber.BMPString, tag);
        return Result<Asn1BmpString>.Success(new(tag, value));
    }
}
