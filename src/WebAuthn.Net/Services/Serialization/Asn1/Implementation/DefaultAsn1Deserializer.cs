using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Implementation;

/// <summary>
///     Default implementation of <see cref="IAsn1Deserializer" />.
/// </summary>
public class DefaultAsn1Deserializer : IAsn1Deserializer
{
    /// <summary>
    ///     Constructs <see cref="DefaultAsn1Deserializer" />.
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultAsn1Deserializer(ILogger<DefaultAsn1Deserializer> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        Logger = logger;
    }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultAsn1Deserializer> Logger { get; }

    /// <inheritdoc />
    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    public virtual Result<AbstractAsn1Element?> Deserialize(byte[] input, AsnEncodingRules encodingRules)
    {
        try
        {
            var reader = new AsnReader(input, encodingRules);
            if (!reader.HasData)
            {
                return Result<AbstractAsn1Element?>.Success(null);
            }

            var rootResult = Read(reader);
            if (rootResult.HasError)
            {
                return Result<AbstractAsn1Element?>.Fail();
            }

            return Result<AbstractAsn1Element?>.Success(rootResult.Ok);
        }
        // ReSharper disable once EmptyGeneralCatchClause
        catch (Exception exception)
        {
            Logger.WarnDeserializationError(exception);
            return Result<AbstractAsn1Element?>.Fail();
        }
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
            UniversalTagNumber.Boolean => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.Integer => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.BitString => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.OctetString => Transform(ReadOctetString(reader, tag)),
            UniversalTagNumber.Null => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.ObjectIdentifier => Transform(ReadObjectIdentifier(reader, tag)),
            UniversalTagNumber.ObjectDescriptor => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.External => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.Real => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.Enumerated => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.Embedded => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.UTF8String => Transform(ReadUtf8String(reader, tag)),
            UniversalTagNumber.RelativeObjectIdentifier => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.Time => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.Sequence => Transform(ReadSequence(reader, tag)),
            UniversalTagNumber.Set => Transform(ReadSet(reader, tag)),
            UniversalTagNumber.NumericString => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.PrintableString => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.T61String => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.VideotexString => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.IA5String => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.UtcTime => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.GeneralizedTime => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.GraphicString => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.VisibleString => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.GeneralString => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.UniversalString => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.UnrestrictedCharacterString => Transform(ReadRaw(reader, tag)),
            UniversalTagNumber.BMPString => Transform(ReadRaw(reader, tag)),
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

    private static Result<Asn1OctetString> ReadOctetString(
        AsnReader reader,
        Asn1Tag tag)
    {
        var value = reader.ReadOctetString(tag);
        return Result<Asn1OctetString>.Success(new(tag, value));
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
}

/// <summary>
///     Extension methods for logging ASN.1 deserialization.
/// </summary>
public static class DefaultAuthenticationCeremonyServiceLoggingExtensions
{
    private static readonly Action<ILogger, Exception?> WarnDeserializationErrorCallback = LoggerMessage.Define(
        LogLevel.Warning,
        new(default, nameof(WarnDeserializationError)),
        "An error occurred during the deserialization");

    /// <summary>
    ///     An error occurred during the deserialization
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">Exception.</param>
    public static void WarnDeserializationError(this ILogger logger, Exception? exception)
    {
        ArgumentNullException.ThrowIfNull(logger);
        if (logger.IsEnabled(LogLevel.Warning))
        {
            WarnDeserializationErrorCallback(logger, exception);
        }
    }
}
