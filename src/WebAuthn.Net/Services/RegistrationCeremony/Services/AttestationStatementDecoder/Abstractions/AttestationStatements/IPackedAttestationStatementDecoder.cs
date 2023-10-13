using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementDecoder.Abstractions.AttestationStatements;

public interface IPackedAttestationStatementDecoder
{
    Result<PackedAttestationStatement> Decode(CborMap attStmt);
}
