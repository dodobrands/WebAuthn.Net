using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models;

namespace WebAuthn.Net.Services.Cryptography.Cose;

public interface ICoseKeyDecoder
{
    Result<CoseKeyDecodeResult> Decode(byte[] encodedCoseKey);
}
