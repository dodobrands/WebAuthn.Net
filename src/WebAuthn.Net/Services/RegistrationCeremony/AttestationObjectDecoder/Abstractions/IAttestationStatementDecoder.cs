using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements.Abstractions;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject;

public interface IAttestationStatementDecoder
{
    Result<AbstractAttestationStatement> Decode(CborMap attStmt, AttestationStatementFormat attestationStatementFormat);
}
