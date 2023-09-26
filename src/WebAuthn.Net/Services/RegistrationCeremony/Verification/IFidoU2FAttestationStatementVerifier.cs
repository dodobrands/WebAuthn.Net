﻿using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;

namespace WebAuthn.Net.Services.RegistrationCeremony.Verification;

public interface IFidoU2FAttestationStatementVerifier
{
    Result<AttestationStatementVerificationResult> Verify(
        FidoU2FAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash);
}
