using System;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Protocol.Models;

namespace WebAuthn.Net.Services.Serialization.Cbor.Protocol.Implementation;

public class DefaultCborDecoder : ICborDecoder
{
    public Result<CborRoot> TryDecode(ReadOnlySpan<byte> input)
    {
        throw new NotImplementedException();
    }
}
