using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cose.Models;

namespace WebAuthn.Net.Services.Serialization.Cose;

/// <summary>
///     Deserializer for public keys in COSE format.
/// </summary>
public interface ICoseKeyDeserializer
{
    /// <summary>
    ///     Deserializes the public key encoded in COSE format into a typed representation.
    /// </summary>
    /// <param name="encodedCoseKey">Public key, encoded in COSE format.</param>
    /// <returns>If deserialization was successful - the result contains <see cref="SuccessfulCoseKeyDeserializeResult" />, otherwise - the result indicates that an error occurred during deserialization.</returns>
    Result<SuccessfulCoseKeyDeserializeResult> Deserialize(byte[] encodedCoseKey);
}
