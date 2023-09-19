using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject;

public interface IAttestationObjectDecoder
{
    DecodedAttestationObject Decode(byte[] attestationObject);
}
