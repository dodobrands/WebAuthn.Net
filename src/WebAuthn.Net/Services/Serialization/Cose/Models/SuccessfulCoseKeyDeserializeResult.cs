using System;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cose.Models;

/// <summary>
///     The result of successful deserialization of the public key in COSE format.
/// </summary>
public class SuccessfulCoseKeyDeserializeResult
{
    /// <summary>
    ///     Constructs <see cref="SuccessfulCoseKeyDeserializeResult" />.
    /// </summary>
    /// <param name="coseKey">Deserialized public key in COSE format. </param>
    /// <param name="bytesConsumed">The number of bytes consumed from the source during deserialization.</param>
    /// <exception cref="ArgumentNullException"><paramref name="coseKey" /> is <see langword="null" /></exception>
    public SuccessfulCoseKeyDeserializeResult(AbstractCoseKey coseKey, int bytesConsumed)
    {
        ArgumentNullException.ThrowIfNull(coseKey);
        CoseKey = coseKey;
        BytesConsumed = bytesConsumed;
    }

    /// <summary>
    ///     Deserialized public key in COSE format.
    /// </summary>
    public AbstractCoseKey CoseKey { get; }

    /// <summary>
    ///     The number of bytes consumed from the source during deserialization.
    /// </summary>
    public int BytesConsumed { get; }
}
