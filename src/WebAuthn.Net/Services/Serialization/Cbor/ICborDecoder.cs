using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Models;

namespace WebAuthn.Net.Services.Serialization.Cbor;

public interface ICborDecoder
{
    Result<CborRoot> TryDecode(byte[] input);
}
