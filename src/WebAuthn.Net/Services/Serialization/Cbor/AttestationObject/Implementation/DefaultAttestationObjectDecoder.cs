using System;
using System.Formats.Cbor;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Implementation;

public class DefaultAttestationObjectDecoder : IAttestationObjectDecoder
{
    public DecodedAttestationObject Decode(byte[] attestationObject)
    {
        var reader = new CborReader(attestationObject, CborConformanceMode.Ctap2Canonical);
        throw new NotImplementedException();
    }
}
