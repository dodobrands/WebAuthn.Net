using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models;

namespace WebAuthn.Net.Services.Serialization.Cbor.Format;

public interface ICborDecoder
{
    Result<CborRoot> TryDecode(byte[] input);
}
