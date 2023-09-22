using WebAuthn.Net.Services.Cryptography.Cose.Models.Abstractions;

namespace WebAuthn.Net.Services.Cryptography.Cose.Models;

public class CoseKeyDecodeResult
{
    public CoseKeyDecodeResult(AbstractCoseKey coseKey, int bytesConsumed)
    {
        CoseKey = coseKey;
        BytesConsumed = bytesConsumed;
    }

    public AbstractCoseKey CoseKey { get; }

    public int BytesConsumed { get; }
}
