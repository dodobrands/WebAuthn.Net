using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.AttestationStatements;

public interface IPackedAttestationStatementDecoder
{
    Result<PackedAttestationStatement> Decode(CborMap attStmt);
}
