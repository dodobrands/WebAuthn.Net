using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject;

public interface IAttestationObjectDecoder
{
    Result<DecodedAttestationObject> Decode(byte[] attestationObject);
}
