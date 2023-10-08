using System;
using System.ComponentModel;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models.AttestationStatements.Abstractions;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models;

public class AttestationObject
{
    public AttestationObject(
        AttestationStatementFormat fmt,
        AbstractAttestationStatement attStmt,
        AuthenticatorData authData)
    {
        if (!Enum.IsDefined(typeof(AttestationStatementFormat), fmt))
        {
            throw new InvalidEnumArgumentException(nameof(fmt), (int) fmt, typeof(AttestationStatementFormat));
        }

        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(authData);
        Fmt = fmt;
        AttStmt = attStmt;
        AuthData = authData;
    }

    public AttestationStatementFormat Fmt { get; }

    public AbstractAttestationStatement AttStmt { get; }

    public AuthenticatorData AuthData { get; }
}
