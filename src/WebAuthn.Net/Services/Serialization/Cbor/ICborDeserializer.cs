using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Models;

namespace WebAuthn.Net.Services.Serialization.Cbor;

/// <summary>
///     CBOR format deserializer.
/// </summary>
public interface ICborDeserializer
{
    /// <summary>
    ///     Deserializes CBOR into a tree and returns a result containing its root.
    /// </summary>
    /// <param name="input">Array of bytes containing the structure encoded in CBOR format.</param>
    /// <returns>If the deserialization was successful, the result contains a <see cref="CborRoot" />, otherwise the result indicates that an error occurred during deserialization.</returns>
    Result<CborRoot> Deserialize(byte[] input);
}
