using System;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Protocol.Models;

namespace WebAuthn.Net.Services.Serialization.Cbor.Protocol;

public interface ICborDecoder
{
    Result<CborRoot> TryDecode(ReadOnlySpan<byte> input);
}
