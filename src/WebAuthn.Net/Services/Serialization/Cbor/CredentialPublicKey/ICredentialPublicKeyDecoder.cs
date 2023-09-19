using WebAuthn.Net.Services.Serialization.Cbor.CredentialPublicKey.Models;

namespace WebAuthn.Net.Services.Serialization.Cbor.CredentialPublicKey;

public interface ICredentialPublicKeyDecoder
{
    DecodedCredentialPublicKey Decode(byte[] credentialPublicKey);
}
