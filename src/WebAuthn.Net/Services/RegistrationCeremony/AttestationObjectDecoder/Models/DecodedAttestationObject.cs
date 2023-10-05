using System;
using System.ComponentModel;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AuthenticatorData;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models;

public class DecodedAttestationObject
{
    public DecodedAttestationObject(
        AttestationStatementFormat fmt,
        AbstractAttestationStatement attStmt,
        DecodedAuthenticatorData authData,
        byte[] rawAuthData)
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
        RawAuthData = rawAuthData;
    }

    public AttestationStatementFormat Fmt { get; }

    public AbstractAttestationStatement AttStmt { get; }

    public DecodedAuthenticatorData AuthData { get; }

    public byte[] RawAuthData { get; }
}
