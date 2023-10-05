using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements.Abstractions;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Models;

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
