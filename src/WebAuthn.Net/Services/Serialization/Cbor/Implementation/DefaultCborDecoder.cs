using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Implementation;

public class DefaultCborDecoder : ICborDecoder
{
    private readonly ILogger<DefaultCborDecoder> _logger;

    public DefaultCborDecoder(ILogger<DefaultCborDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    public Result<CborRoot> Decode(byte[] input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var reader = new CborReader(input, CborConformanceMode.Ctap2Canonical);
        var rootResult = Read(reader);
        if (rootResult.HasError)
        {
            return Result<CborRoot>.Fail();
        }

        var bytesRead = ComputeBytesRead(input, reader);
        var root = new CborRoot(rootResult.Ok, bytesRead);
        return Result<CborRoot>.Success(root);
    }

    private static int ComputeBytesRead(ReadOnlySpan<byte> input, CborReader reader)
    {
        return input.Length - reader.BytesRemaining;
    }

    private Result<AbstractCborObject> Read(CborReader reader)
    {
        var state = reader.PeekState();
        switch (state)
        {
            case CborReaderState.Undefined:
                {
                    _logger.CborReaderUndefined();
                    return Result<AbstractCborObject>.Fail();
                }
            case CborReaderState.UnsignedInteger:
                {
                    return Transform(ReadUnsignedInteger(reader));
                }
            case CborReaderState.NegativeInteger:
                {
                    return Transform(ReadNegativeInteger(reader));
                }
            case CborReaderState.ByteString:
                {
                    return Transform(ReadByteString(reader));
                }
            case CborReaderState.StartIndefiniteLengthByteString:
                {
                    _logger.CborReaderStartIndefiniteLengthByteString();
                    return Result<AbstractCborObject>.Fail();
                }
            case CborReaderState.EndIndefiniteLengthByteString:
                {
                    _logger.CborReaderEndIndefiniteLengthByteString();
                    return Result<AbstractCborObject>.Fail();
                }
            case CborReaderState.TextString:
                {
                    return Transform(ReadTextString(reader));
                }
            case CborReaderState.StartIndefiniteLengthTextString:
                {
                    _logger.CborReaderStartIndefiniteLengthTextString();
                    return Result<AbstractCborObject>.Fail();
                }
            case CborReaderState.EndIndefiniteLengthTextString:
                {
                    _logger.CborReaderEndIndefiniteLengthTextString();
                    return Result<AbstractCborObject>.Fail();
                }
            case CborReaderState.StartArray:
                {
                    return Transform(ReadArray(reader));
                }
            case CborReaderState.EndArray:
                {
                    _logger.CborReaderEndArray();
                    return Result<AbstractCborObject>.Fail();
                }
            case CborReaderState.StartMap:
                {
                    return Transform(ReadMap(reader));
                }
            case CborReaderState.EndMap:
                {
                    _logger.CborReaderEndMap();
                    return Result<AbstractCborObject>.Fail();
                }
            case CborReaderState.Tag:
                {
                    _logger.CborReaderTag();
                    return Result<AbstractCborObject>.Fail();
                }
            case CborReaderState.SimpleValue:
                {
                    return ReadSimpleValue(reader);
                }
            case CborReaderState.HalfPrecisionFloat:
                {
                    return Transform(ReadHalfPrecisionFloat(reader));
                }
            case CborReaderState.SinglePrecisionFloat:
                {
                    return Transform(ReadSinglePrecisionFloat(reader));
                }
            case CborReaderState.DoublePrecisionFloat:
                {
                    return Transform(ReadDoublePrecisionFloat(reader));
                }
            case CborReaderState.Null:
                {
                    return Transform(ReadNull(reader));
                }
            case CborReaderState.Boolean:
                {
                    return Transform(ReadBoolean(reader));
                }
            case CborReaderState.Finished:
                {
                    _logger.CborReaderFinished();
                    return Result<AbstractCborObject>.Fail();
                }
            default:
                {
                    _logger.CborReaderUnhandledState();
                    return Result<AbstractCborObject>.Fail();
                }
        }
    }

    private static Result<AbstractCborObject> Transform<TSource>(Result<TSource> source)
        where TSource : AbstractCborObject
    {
        return source.HasError
            ? Result<AbstractCborObject>.Fail()
            : Result<AbstractCborObject>.Success(source.Ok);
    }

    private static Result<CborUnsignedInteger> ReadUnsignedInteger(CborReader reader)
    {
        var value = reader.ReadUInt64();
        var result = new CborUnsignedInteger(value);
        return Result<CborUnsignedInteger>.Success(result);
    }

    private static Result<CborNegativeInteger> ReadNegativeInteger(CborReader reader)
    {
        var value = reader.ReadCborNegativeIntegerRepresentation();
        var result = new CborNegativeInteger(value);
        return Result<CborNegativeInteger>.Success(result);
    }

    private static Result<CborByteString> ReadByteString(CborReader reader)
    {
        var value = reader.ReadByteString();
        var result = new CborByteString(value);
        return Result<CborByteString>.Success(result);
    }

    private static Result<CborTextString> ReadTextString(CborReader reader)
    {
        var value = reader.ReadTextString();
        var result = new CborTextString(value);
        return Result<CborTextString>.Success(result);
    }

    private Result<CborArray> ReadArray(CborReader reader)
    {
        var count = reader.ReadStartArray();
        if (!count.HasValue)
        {
            _logger.ArrayIndefiniteLength();
            return Result<CborArray>.Fail();
        }

        var accumulator = new List<AbstractCborObject>(count.Value);
        CborReaderState state;
        while ((state = reader.PeekState()) is not (CborReaderState.EndArray or CborReaderState.Finished))
        {
            var readResult = Read(reader);
            if (readResult.HasError)
            {
                return Result<CborArray>.Fail();
            }

            accumulator.Add(readResult.Ok);
        }

        if (state == CborReaderState.EndArray)
        {
            reader.ReadEndArray();
        }

        var result = new CborArray(accumulator);
        return Result<CborArray>.Success(result);
    }

    private Result<CborMap> ReadMap(CborReader reader)
    {
        var count = reader.ReadStartMap();
        if (!count.HasValue)
        {
            _logger.MapIndefiniteLength();
            return Result<CborMap>.Fail();
        }

        var accumulator = new Dictionary<AbstractCborObject, AbstractCborObject>(count.Value);
        CborReaderState state;
        while ((state = reader.PeekState()) is not (CborReaderState.EndMap or CborReaderState.Finished))
        {
            var key = Read(reader);
            if (key.HasError)
            {
                return Result<CborMap>.Fail();
            }

            var value = Read(reader);
            if (value.HasError)
            {
                return Result<CborMap>.Fail();
            }

            accumulator.Add(key.Ok, value.Ok);
        }

        if (state == CborReaderState.EndMap)
        {
            reader.ReadEndMap();
        }

        var result = new CborMap(accumulator);
        return Result<CborMap>.Success(result);
    }

    private Result<AbstractCborObject> ReadSimpleValue(CborReader reader)
    {
        var simpleValue = reader.ReadSimpleValue();
        switch (simpleValue)
        {
            case CborSimpleValue.False:
                return Result<AbstractCborObject>.Success(CborBoolean.False);
            case CborSimpleValue.True:
                return Result<AbstractCborObject>.Success(CborBoolean.True);
            case CborSimpleValue.Null:
                return Result<AbstractCborObject>.Success(CborNull.Instance);
            case CborSimpleValue.Undefined:
                return Result<AbstractCborObject>.Success(CborUndefined.Instance);
            default:
                {
                    _logger.UnsupportedSimpleValue();
                    return Result<AbstractCborObject>.Fail();
                }
        }
    }

    private static Result<CborHalfPrecisionFloat> ReadHalfPrecisionFloat(CborReader reader)
    {
        var value = reader.ReadHalf();
        var result = new CborHalfPrecisionFloat(value);
        return Result<CborHalfPrecisionFloat>.Success(result);
    }

    private static Result<CborSinglePrecisionFloat> ReadSinglePrecisionFloat(CborReader reader)
    {
        var value = reader.ReadSingle();
        var result = new CborSinglePrecisionFloat(value);
        return Result<CborSinglePrecisionFloat>.Success(result);
    }

    private static Result<CborDoublePrecisionFloat> ReadDoublePrecisionFloat(CborReader reader)
    {
        var value = reader.ReadDouble();
        var result = new CborDoublePrecisionFloat(value);
        return Result<CborDoublePrecisionFloat>.Success(result);
    }

    private static Result<CborNull> ReadNull(CborReader reader)
    {
        reader.ReadNull();
        var result = CborNull.Instance;
        return Result<CborNull>.Success(result);
    }

    private static Result<CborBoolean> ReadBoolean(CborReader reader)
    {
        var value = reader.ReadBoolean();
        var result = value ? CborBoolean.True : CborBoolean.False;
        return Result<CborBoolean>.Success(result);
    }
}

public static partial class DefaultCborDecoderLoggingExtensions
{
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The CborReader is in an 'Undefined' state, unable to perform reading")]
    public static partial void CborReaderUndefined(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Attempt to start reading a CBOR byte string with indefinite length, while all items must have a definite length")]
    public static partial void CborReaderStartIndefiniteLengthByteString(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Attempt to end reading a CBOR byte string with indefinite length, while all items must have a definite length")]
    public static partial void CborReaderEndIndefiniteLengthByteString(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Attempt to start reading a CBOR text string with indefinite length, while all items must have a definite length")]
    public static partial void CborReaderStartIndefiniteLengthTextString(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Attempt to end reading a CBOR text string with indefinite length, while all items must have a definite length")]
    public static partial void CborReaderEndIndefiniteLengthTextString(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The CborReader is in an 'EndArray' state, unable to perform reading")]
    public static partial void CborReaderEndArray(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The CborReader is in an 'EndMap' state, unable to perform reading")]
    public static partial void CborReaderEndMap(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "According to the specification, the use of tags is forbidden")]
    public static partial void CborReaderTag(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The CborReader is in an 'Finished' state, unable to perform reading")]
    public static partial void CborReaderFinished(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Unhandled state encountered")]
    public static partial void CborReaderUnhandledState(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "An array with indefinite length was detected, and all items must have a definite length")]
    public static partial void ArrayIndefiniteLength(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "A map with indefinite length was detected, and all items must have a definite length")]
    public static partial void MapIndefiniteLength(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Attempt to read unsupported CBOR simple value")]
    public static partial void UnsupportedSimpleValue(this ILogger logger);
}
