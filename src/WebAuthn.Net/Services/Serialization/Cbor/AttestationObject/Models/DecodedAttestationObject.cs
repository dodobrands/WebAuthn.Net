using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements.Abstractions;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.Enums;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models;

public class DecodedAttestationObject
{
    public DecodedAttestationObject(AttestationStatementFormat fmt, AbstractAttestationStatement attStmt)
    {
        Fmt = fmt;
        AttStmt = attStmt;
    }

    public AttestationStatementFormat Fmt { get; }

    public AbstractAttestationStatement AttStmt { get; }
}
