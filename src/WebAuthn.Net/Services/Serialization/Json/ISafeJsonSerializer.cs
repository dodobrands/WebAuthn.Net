using System;
using System.Text.Json;
using WebAuthn.Net.Models;

namespace WebAuthn.Net.Services.Serialization.Json;

/// <summary>
///     Safe (exceptionless) JSON serializer.
/// </summary>
public interface ISafeJsonSerializer
{
    /// <summary>
    ///     Deserializes a non-null object of the specified type from a string containing JSON.
    /// </summary>
    /// <param name="json">A string containing JSON.</param>
    /// <param name="options">Options for the <see cref="JsonSerializer" />.</param>
    /// <typeparam name="TValue">The type of object to deserialize.</typeparam>
    /// <returns>If the deserialization was successful and the obtained object is not <see langword="null" />, then the result contains <typeparamref name="TValue" />, otherwise the result indicates that an error occurred during deserialization.</returns>
    Result<TValue> DeserializeNonNullable<TValue>(string json, JsonSerializerOptions? options = null);

    /// <summary>
    ///     Deserializes a non-null object of the specified type from a ReadOnlySpan of bytes containing a utf8 string with JSON.
    /// </summary>
    /// <param name="utf8Json">Utf8 string containing JSON, represented as a ReadOnlySpan of bytes.</param>
    /// <param name="options">Options for the <see cref="JsonSerializer" />.</param>
    /// <typeparam name="TValue">The type of object to deserialize.</typeparam>
    /// <returns>If the deserialization was successful and the obtained object is not <see langword="null" />, then the result contains <typeparamref name="TValue" />, otherwise the result indicates that an error occurred during deserialization.</returns>
    Result<TValue> DeserializeNonNullable<TValue>(ReadOnlySpan<byte> utf8Json, JsonSerializerOptions? options = null);

    /// <summary>
    ///     Serializes a value of a specified type into a utf8 string and returns it as a byte array.
    /// </summary>
    /// <param name="value">The value that should be serialized.</param>
    /// <param name="options">Options for the <see cref="JsonSerializer" />.</param>
    /// <typeparam name="TValue">The type of the object to serialize.</typeparam>
    /// <returns>If the serialization was successful, the result contains a byte array, otherwise the result indicates that an error occurred during serialization.</returns>
    Result<byte[]> SerializeToUtf8Bytes<TValue>(TValue value, JsonSerializerOptions? options = null);
}
