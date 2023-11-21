using System;
using System.Text.Json;
using WebAuthn.Net.Models;

namespace WebAuthn.Net.Services.Serialization.Json;

public interface ISafeJsonSerializer
{
    Result<TValue> DeserializeNonNullable<TValue>(string json, JsonSerializerOptions? options = null);

    Result<TValue> DeserializeNonNullable<TValue>(ReadOnlySpan<byte> utf8Json, JsonSerializerOptions? options = null);

    Result<byte[]> SerializeToUtf8Bytes<TValue>(TValue value, JsonSerializerOptions? options = null);
}
