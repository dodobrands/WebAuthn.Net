using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.Enums;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models;

public class DecodedAttestationObject
{
    public DecodedAttestationObject(AttestationStatementFormat fmt)
    {
        Fmt = fmt;
    }

    public AttestationStatementFormat Fmt { get; }
}
