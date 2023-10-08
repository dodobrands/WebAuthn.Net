using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models.AttestationStatements.Abstractions;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Abstractions;

public interface IAttestationStatementDecoder
{
    Result<AbstractAttestationStatement> Decode(CborMap attStmt, AttestationStatementFormat attestationStatementFormat);
}
