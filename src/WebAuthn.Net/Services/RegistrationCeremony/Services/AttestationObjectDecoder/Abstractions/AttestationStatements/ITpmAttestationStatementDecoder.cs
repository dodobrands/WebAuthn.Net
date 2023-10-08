using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Abstractions.AttestationStatements;

public interface ITpmAttestationStatementDecoder
{
    Result<TpmAttestationStatement> Decode(CborMap attStmt);
}
