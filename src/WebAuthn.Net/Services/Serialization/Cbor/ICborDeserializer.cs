using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Models;

namespace WebAuthn.Net.Services.Serialization.Cbor;

public interface ICborDeserializer
{
    Result<CborRoot> Deserialize(byte[] input);
}
