using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models;

public class CborRoot
{
    public CborRoot(AbstractCborObject root, int bytesConsumed)
    {
        Root = root;
        BytesConsumed = bytesConsumed;
    }

    public AbstractCborObject Root { get; }

    public int BytesConsumed { get; }
}
