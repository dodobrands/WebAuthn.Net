using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Abstractions.AttestationStatements;

public interface INoneAttestationStatementDecoder
{
    Result<NoneAttestationStatement> Decode(CborMap attStmt);
}
