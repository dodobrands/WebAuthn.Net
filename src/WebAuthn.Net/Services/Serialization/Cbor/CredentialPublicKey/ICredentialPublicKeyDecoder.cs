using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.CredentialPublicKey.Models;

namespace WebAuthn.Net.Services.Serialization.Cbor.CredentialPublicKey;

public interface ICredentialPublicKeyDecoder
{
    Result<CredentialPublicKeyDecodeResult> Decode(byte[] credentialPublicKey);
}
