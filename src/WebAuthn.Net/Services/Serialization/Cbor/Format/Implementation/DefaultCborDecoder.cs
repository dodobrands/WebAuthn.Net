using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Format.Implementation;

public class DefaultCborDecoder : ICborDecoder
{
    public Result<CborRoot> TryDecode(byte[] input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var reader = new CborReader(input, CborConformanceMode.Ctap2Canonical);
        var rootResult = Read(reader);
        if (rootResult.HasError)
        {
            return Result<CborRoot>.Failed(rootResult.Error);
        }

        var bytesRead = ComputeBytesRead(input, reader);
        var root = new CborRoot(rootResult.Ok, bytesRead);
        return Result<CborRoot>.Success(root);
    }

    private static int ComputeBytesRead(ReadOnlySpan<byte> input, CborReader reader)
    {
        return input.Length - reader.BytesRemaining;
    }

    private static Result<AbstractCborObject> Read(CborReader reader)
    {
        var state = reader.PeekState();
        return state switch
        {
            CborReaderState.Undefined => Result<AbstractCborObject>.Failed($"An error occurred when attempting to read from the '{nameof(CborReaderState.Undefined)}' of the {nameof(CborReader)}"),
            CborReaderState.UnsignedInteger => Transform(ReadUnsignedInteger(reader)),
            CborReaderState.NegativeInteger => Transform(ReadNegativeInteger(reader)),
            CborReaderState.ByteString => Transform(ReadByteString(reader)),
            CborReaderState.StartIndefiniteLengthByteString => Result<AbstractCborObject>.Failed("Attempting to start reading a CBOR byte string with indefinite length. All items must have a definite length."),
            CborReaderState.EndIndefiniteLengthByteString => Result<AbstractCborObject>.Failed("Attempting to end reading a CBOR byte string with indefinite length. All items must have a definite length."),
            CborReaderState.TextString => Transform(ReadTextString(reader)),
            CborReaderState.StartIndefiniteLengthTextString => Result<AbstractCborObject>.Failed("Attempting to start reading a CBOR text string with indefinite length. All items must have a definite length."),
            CborReaderState.EndIndefiniteLengthTextString => Result<AbstractCborObject>.Failed("Attempting to end reading a CBOR text string with indefinite length. All items must have a definite length."),
            CborReaderState.StartArray => Transform(ReadArray(reader)),
            CborReaderState.EndArray => Result<AbstractCborObject>.Failed($"Unhandled state. Was {state}"),
            CborReaderState.StartMap => Transform(ReadMap(reader)),
            CborReaderState.EndMap => Result<AbstractCborObject>.Failed($"Unhandled state. Was {state}"),
            CborReaderState.Tag => Result<AbstractCborObject>.Failed("According to the specification, the use of tags is forbidden."),
            CborReaderState.SimpleValue => ReadSimpleValue(reader),
            CborReaderState.HalfPrecisionFloat => Transform(ReadHalfPrecisionFloat(reader)),
            CborReaderState.SinglePrecisionFloat => Transform(ReadSinglePrecisionFloat(reader)),
            CborReaderState.DoublePrecisionFloat => Transform(ReadDoublePrecisionFloat(reader)),
            CborReaderState.Null => Transform(ReadNull(reader)),
            CborReaderState.Boolean => Transform(ReadBoolean(reader)),
            CborReaderState.Finished => Result<AbstractCborObject>.Failed($"Unhandled state. Was {state}"),
            _ => Result<AbstractCborObject>.Failed($"Unhandled state. Was {state}")
        };
    }

    private static Result<AbstractCborObject> Transform<TSource>(Result<TSource> source)
        where TSource : AbstractCborObject
    {
        return source.HasError
            ? Result<AbstractCborObject>.Failed(source.Error)
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

    private static Result<CborArray> ReadArray(CborReader reader)
    {
        var count = reader.ReadStartArray();
        if (!count.HasValue)
        {
            return Result<CborArray>.Failed("An array with indefinite length was detected. All items must have a definite length.");
        }

        var accumulator = new List<AbstractCborObject>(count.Value);
        CborReaderState state;
        while ((state = reader.PeekState()) is not (CborReaderState.EndArray or CborReaderState.Finished))
        {
            var readResult = Read(reader);
            if (readResult.HasError)
            {
                return Result<CborArray>.Failed(readResult.Error);
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

    private static Result<CborMap> ReadMap(CborReader reader)
    {
        var count = reader.ReadStartMap();
        if (!count.HasValue)
        {
            return Result<CborMap>.Failed("A map with indefinite length was detected. All items must have a definite length.");
        }

        var accumulator = new Dictionary<AbstractCborObject, AbstractCborObject>(count.Value);
        CborReaderState state;
        while ((state = reader.PeekState()) is not (CborReaderState.EndMap or CborReaderState.Finished))
        {
            var key = Read(reader);
            if (key.HasError)
            {
                return Result<CborMap>.Failed(key.Error);
            }

            var value = Read(reader);
            if (value.HasError)
            {
                return Result<CborMap>.Failed(value.Error);
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

    private static Result<AbstractCborObject> ReadSimpleValue(CborReader reader)
    {
        var simpleValue = reader.ReadSimpleValue();
        return simpleValue switch
        {
            CborSimpleValue.False => Result<AbstractCborObject>.Success(CborBoolean.False),
            CborSimpleValue.True => Result<AbstractCborObject>.Success(CborBoolean.True),
            CborSimpleValue.Null => Result<AbstractCborObject>.Success(CborNull.Instance),
            CborSimpleValue.Undefined => Result<AbstractCborObject>.Success(CborUndefined.Instance),
            _ => Result<AbstractCborObject>.Failed("Attempting to read an unsupported CBOR simple value type.")
        };
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

    //Boolean
}
