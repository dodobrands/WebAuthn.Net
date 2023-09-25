using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements.Abstractions;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models.AttestationStatementVerifier;

public class AttestationStatementVerificationRequest
{
    public AttestationStatementVerificationRequest(
        AttestationStatementFormat fmt,
        AbstractAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        Fmt = fmt;
        AttStmt = attStmt;
        AuthData = authData;
        ClientDataHash = clientDataHash;
    }

    public AttestationStatementFormat Fmt { get; }
    public AbstractAttestationStatement AttStmt { get; }
    public AttestationStatementVerificationAuthData AuthData { get; }
    public byte[] ClientDataHash { get; }
}
