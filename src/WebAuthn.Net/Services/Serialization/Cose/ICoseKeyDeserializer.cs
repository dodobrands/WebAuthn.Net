using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cose.Models;

namespace WebAuthn.Net.Services.Serialization.Cose;

public interface ICoseKeyDeserializer
{
    Result<CoseKeyDeserializeResult> Deserialize(byte[] encodedCoseKey);
}
