using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models;

/// <summary>
///     The root of the decoded object in CBOR format.
/// </summary>
public class CborRoot
{
    /// <summary>
    ///     Constructs <see cref="CborRoot" />.
    /// </summary>
    /// <param name="root">The root element of the decoded object in CBOR format.</param>
    /// <param name="bytesConsumed">The number of bytes consumed during decoding.</param>
    public CborRoot(AbstractCborObject root, int bytesConsumed)
    {
        Root = root;
        BytesConsumed = bytesConsumed;
    }

    /// <summary>
    ///     The root element of the decoded object in CBOR format.
    /// </summary>
    public AbstractCborObject Root { get; }

    /// <summary>
    ///     The number of bytes consumed during decoding.
    /// </summary>
    public int BytesConsumed { get; }
}
