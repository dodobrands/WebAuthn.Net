using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cose.Models;

public class CoseKeyDeserializeResult
{
    public CoseKeyDeserializeResult(AbstractCoseKey coseKey, int bytesConsumed)
    {
        CoseKey = coseKey;
        BytesConsumed = bytesConsumed;
    }

    public AbstractCoseKey CoseKey { get; }

    public int BytesConsumed { get; }
}
