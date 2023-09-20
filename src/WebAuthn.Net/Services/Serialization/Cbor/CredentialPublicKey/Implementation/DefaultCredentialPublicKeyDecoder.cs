using System;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.CredentialPublicKey.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Format;

namespace WebAuthn.Net.Services.Serialization.Cbor.CredentialPublicKey.Implementation;

public class DefaultCredentialPublicKeyDecoder : ICredentialPublicKeyDecoder
{
    private readonly ICborDecoder _cborDecoder;

    public DefaultCredentialPublicKeyDecoder(ICborDecoder cborDecoder)
    {
        ArgumentNullException.ThrowIfNull(cborDecoder);
        _cborDecoder = cborDecoder;
    }

    public Result<CredentialPublicKeyDecodeResult> Decode(byte[] credentialPublicKey)
    {
        ArgumentNullException.ThrowIfNull(credentialPublicKey);
        var cborResult = _cborDecoder.TryDecode(credentialPublicKey);
        throw new NotImplementedException();
    }
}
