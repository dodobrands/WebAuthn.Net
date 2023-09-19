using System;
using WebAuthn.Net.Services.Serialization.Cbor.CredentialPublicKey.Models;

namespace WebAuthn.Net.Services.Serialization.Cbor.CredentialPublicKey.Implementation;

public class DefaultCredentialPublicKeyDecoder : ICredentialPublicKeyDecoder
{
    public DecodedCredentialPublicKey Decode(byte[] credentialPublicKey)
    {
        throw new NotImplementedException();
    }
}
