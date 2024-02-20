using System;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;

namespace WebAuthn.Net.Services.Serialization.Json.Implementation;

/// <summary>
///     Default implementation of <see cref="ISafeJsonSerializer" />.
/// </summary>
public class DefaultSafeJsonSerializer : ISafeJsonSerializer
{
    /// <summary>
    ///     Constructs <see cref="DefaultSafeJsonSerializer" />
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultSafeJsonSerializer(ILogger<DefaultSafeJsonSerializer> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        Logger = logger;
    }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultSafeJsonSerializer> Logger { get; }

    /// <inheritdoc />
    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    public virtual Result<TValue> DeserializeNonNullable<TValue>(string json, JsonSerializerOptions? options = null)
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

    /// <inheritdoc />
    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    public virtual Result<TValue> DeserializeNonNullable<TValue>(ReadOnlySpan<byte> utf8Json, JsonSerializerOptions? options = null)
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

    /// <inheritdoc />
    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    public virtual Result<byte[]> SerializeToUtf8Bytes<TValue>(TValue value, JsonSerializerOptions? options = null)
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

/// <summary>
///     Extension methods for logging the safe (exceptionless) JSON serializer.
/// </summary>
public static partial class DefaultSafeJsonSerializerLoggingExtensions
{
    private static readonly Action<ILogger, Exception?> WarnDeserializationErrorCallback = LoggerMessage.Define(
        LogLevel.Warning,
        new(default, nameof(WarnDeserializationError)),
        "An error occurred during the deserialization");

    private static readonly Action<ILogger, Exception?> WarnSerializationToUtf8BytesErrorCallback = LoggerMessage.Define(
        LogLevel.Warning,
        new(default, nameof(WarnSerializationToUtf8BytesError)),
        "An error occurred during the serialization into utf8 byte[]");

    /// <summary>
    ///     An empty value or null was passed as a json string for deserialization
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "An empty value or null was passed as a json string for deserialization")]
    public static partial void WarnEmptyStringInput(this ILogger logger);

    /// <summary>
    ///     During the deserialization of the '{Type}' value, null was received
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="type">The name of the type that was returned as null during the deserialization process.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "During the deserialization of the '{Type}' value, null was received")]
    public static partial void WarnNullDuringDeserialization(this ILogger logger, string type);

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
    ///     An error occurred during the serialization into utf8 byte[]
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">Exception.</param>
    public static void WarnSerializationToUtf8BytesError(this ILogger logger, Exception? exception)
    {
        ArgumentNullException.ThrowIfNull(logger);
        if (logger.IsEnabled(LogLevel.Warning))
        {
            WarnSerializationToUtf8BytesErrorCallback(logger, exception);
        }
    }
}
