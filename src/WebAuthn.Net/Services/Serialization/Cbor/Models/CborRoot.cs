using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models;

public class CborRoot
{
    public CborRoot(AbstractCborObject root, int consumedBytes)
    {
        Root = root;
        ConsumedBytes = consumedBytes;
    }

    public AbstractCborObject Root { get; }

    public int ConsumedBytes { get; }
}
