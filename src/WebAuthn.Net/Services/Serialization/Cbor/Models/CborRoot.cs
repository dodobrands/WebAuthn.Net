using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Format.Models;

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
