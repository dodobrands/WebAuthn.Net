using System;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;

namespace WebAuthn.Net.Services.Serialization.Json.Implementation;

public class DefaultSafeJsonSerializer : ISafeJsonSerializer
{
    public DefaultSafeJsonSerializer(ILogger<DefaultSafeJsonSerializer> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        Logger = logger;
    }

    protected ILogger<DefaultSafeJsonSerializer> Logger { get; }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    public Result<TValue> DeserializeNonNullable<TValue>(string json, JsonSerializerOptions? options = null)
    {
        try
        {
            if (string.IsNullOrEmpty(json))
            {
                Logger.WarnEmptyStringInput();
                return Result<TValue>.Fail();
            }

            var deserialized = JsonSerializer.Deserialize<TValue>(json, options);
            if (deserialized is null)
            {
                Logger.WarnNullDuringDeserialization(typeof(TValue).ToString());
                return Result<TValue>.Fail();
            }

            return Result<TValue>.Success(deserialized);
        }
        catch (Exception exception)
        {
            Logger.WarnDeserializationError(exception);
            return Result<TValue>.Fail();
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    public Result<TValue> DeserializeNonNullable<TValue>(ReadOnlySpan<byte> utf8Json, JsonSerializerOptions? options = null)
    {
        try
        {
            var deserialized = JsonSerializer.Deserialize<TValue>(utf8Json, options);
            if (deserialized is null)
            {
                Logger.WarnNullDuringDeserialization(typeof(TValue).ToString());
                return Result<TValue>.Fail();
            }

            return Result<TValue>.Success(deserialized);
        }
        catch (Exception exception)
        {
            Logger.WarnDeserializationError(exception);
            return Result<TValue>.Fail();
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    public Result<byte[]> SerializeToUtf8Bytes<TValue>(TValue value, JsonSerializerOptions? options = null)
    {
        try
        {
            var serialized = JsonSerializer.SerializeToUtf8Bytes(value, options);
            return Result<byte[]>.Success(serialized);
        }
        catch (Exception exception)
        {
            Logger.WarnSerializationToUtf8BytesError(exception);
            return Result<byte[]>.Fail();
        }
    }
}

public static partial class DefaultSafeJsonSerializerLoggingExtensions
{
    private static readonly Action<ILogger, Exception?> WarnDeserializationErrorCallback = LoggerMessage.Define(
        LogLevel.Warning,
        new(-1, nameof(WarnDeserializationError)),
        "An error occurred during the deserialization");

    private static readonly Action<ILogger, Exception?> WarnSerializationToUtf8BytesErrorCallback = LoggerMessage.Define(
        LogLevel.Warning,
        new(-1, nameof(WarnSerializationToUtf8BytesError)),
        "An error occurred during the serialization into utf8 byte[]");

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "An empty value or null was passed as a json string for deserialization")]
    public static partial void WarnEmptyStringInput(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "During the deserialization of the '{Type}' value, null was received")]
    public static partial void WarnNullDuringDeserialization(this ILogger logger, string type);

    public static void WarnDeserializationError(this ILogger logger, Exception? exception)
    {
        ArgumentNullException.ThrowIfNull(logger);
        if (logger.IsEnabled(LogLevel.Warning))
        {
            WarnDeserializationErrorCallback(logger, exception);
        }
    }

    public static void WarnSerializationToUtf8BytesError(this ILogger logger, Exception? exception)
    {
        ArgumentNullException.ThrowIfNull(logger);
        if (logger.IsEnabled(LogLevel.Warning))
        {
            WarnSerializationToUtf8BytesErrorCallback(logger, exception);
        }
    }
}
