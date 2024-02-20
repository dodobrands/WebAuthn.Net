using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Implementation;

/// <summary>
///     Default implementation of <see cref="ICborDeserializer" />.
/// </summary>
public class DefaultCborDeserializer : ICborDeserializer
{
    /// <summary>
    ///     Constructs <see cref="DefaultCborDeserializer" />.
    /// </summary>
    /// <param name="logger">Logger.</param>
    public DefaultCborDeserializer(ILogger<DefaultCborDeserializer> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        Logger = logger;
    }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultCborDeserializer> Logger { get; }

    /// <inheritdoc />
    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    public virtual Result<CborRoot> Deserialize(byte[] input)
    {
        try
        {
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
        // ReSharper disable once EmptyGeneralCatchClause
        catch (Exception exception)
        {
            Logger.WarnDeserializationError(exception);
            return Result<CborRoot>.Fail();
        }
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
                    Logger.CborReaderUndefined();
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
                    Logger.CborReaderStartIndefiniteLengthByteString();
                    return Result<AbstractCborObject>.Fail();
                }
            case CborReaderState.EndIndefiniteLengthByteString:
                {
                    Logger.CborReaderEndIndefiniteLengthByteString();
                    return Result<AbstractCborObject>.Fail();
                }
            case CborReaderState.TextString:
                {
                    return Transform(ReadTextString(reader));
                }
            case CborReaderState.StartIndefiniteLengthTextString:
                {
                    Logger.CborReaderStartIndefiniteLengthTextString();
                    return Result<AbstractCborObject>.Fail();
                }
            case CborReaderState.EndIndefiniteLengthTextString:
                {
                    Logger.CborReaderEndIndefiniteLengthTextString();
                    return Result<AbstractCborObject>.Fail();
                }
            case CborReaderState.StartArray:
                {
                    return Transform(ReadArray(reader));
                }
            case CborReaderState.EndArray:
                {
                    Logger.CborReaderEndArray();
                    return Result<AbstractCborObject>.Fail();
                }
            case CborReaderState.StartMap:
                {
                    return Transform(ReadMap(reader));
                }
            case CborReaderState.EndMap:
                {
                    Logger.CborReaderEndMap();
                    return Result<AbstractCborObject>.Fail();
                }
            case CborReaderState.Tag:
                {
                    Logger.CborReaderTag();
                    return Result<AbstractCborObject>.Fail();
                }
            case CborReaderState.Finished:
                {
                    Logger.CborReaderFinished();
                    return Result<AbstractCborObject>.Fail();
                }
            default:
                {
                    Logger.CborReaderUnhandledState();
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
            Logger.ArrayIndefiniteLength();
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
            Logger.MapIndefiniteLength();
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
}

/// <summary>
///     Extension method for logging of the CBOR deserializer.
/// </summary>
public static partial class DefaultCborDeserializerLoggingExtensions
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

    /// <summary>
    ///     The CborReader is in an 'Undefined' state, unable to perform reading
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The CborReader is in an 'Undefined' state, unable to perform reading")]
    public static partial void CborReaderUndefined(this ILogger logger);

    /// <summary>
    ///     Attempt to start reading a CBOR byte string with indefinite length, while all items must have a definite length
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Attempt to start reading a CBOR byte string with indefinite length, while all items must have a definite length")]
    public static partial void CborReaderStartIndefiniteLengthByteString(this ILogger logger);

    /// <summary>
    ///     Attempt to end reading a CBOR byte string with indefinite length, while all items must have a definite length
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Attempt to end reading a CBOR byte string with indefinite length, while all items must have a definite length")]
    public static partial void CborReaderEndIndefiniteLengthByteString(this ILogger logger);

    /// <summary>
    ///     Attempt to start reading a CBOR text string with indefinite length, while all items must have a definite length
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Attempt to start reading a CBOR text string with indefinite length, while all items must have a definite length")]
    public static partial void CborReaderStartIndefiniteLengthTextString(this ILogger logger);

    /// <summary>
    ///     Attempt to end reading a CBOR text string with indefinite length, while all items must have a definite length
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Attempt to end reading a CBOR text string with indefinite length, while all items must have a definite length")]
    public static partial void CborReaderEndIndefiniteLengthTextString(this ILogger logger);

    /// <summary>
    ///     The CborReader is in an 'EndArray' state, unable to perform reading
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The CborReader is in an 'EndArray' state, unable to perform reading")]
    public static partial void CborReaderEndArray(this ILogger logger);

    /// <summary>
    ///     The CborReader is in an 'EndMap' state, unable to perform reading
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The CborReader is in an 'EndMap' state, unable to perform reading")]
    public static partial void CborReaderEndMap(this ILogger logger);

    /// <summary>
    ///     According to the specification, the use of tags is forbidden
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "According to the specification, the use of tags is forbidden")]
    public static partial void CborReaderTag(this ILogger logger);

    /// <summary>
    ///     The CborReader is in an 'Finished' state, unable to perform reading
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The CborReader is in an 'Finished' state, unable to perform reading")]
    public static partial void CborReaderFinished(this ILogger logger);

    /// <summary>
    ///     Unhandled state encountered
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Unhandled state encountered")]
    public static partial void CborReaderUnhandledState(this ILogger logger);

    /// <summary>
    ///     An array with indefinite length was detected, and all items must have a definite length
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "An array with indefinite length was detected, and all items must have a definite length")]
    public static partial void ArrayIndefiniteLength(this ILogger logger);

    /// <summary>
    ///     A map with indefinite length was detected, and all items must have a definite length
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "A map with indefinite length was detected, and all items must have a definite length")]
    public static partial void MapIndefiniteLength(this ILogger logger);

    /// <summary>
    ///     Attempt to read unsupported CBOR simple value
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Attempt to read unsupported CBOR simple value")]
    public static partial void UnsupportedSimpleValue(this ILogger logger);
}
