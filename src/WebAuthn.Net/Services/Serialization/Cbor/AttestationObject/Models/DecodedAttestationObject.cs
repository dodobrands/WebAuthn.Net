using System;
using System.ComponentModel;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements.Abstractions;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AuthenticatorData;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.Enums;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models;

public class DecodedAttestationObject
{
    public DecodedAttestationObject(
        AttestationStatementFormat fmt,
        AbstractAttestationStatement attStmt,
        DecodedAuthenticatorData authData)
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

    public DecodedAuthenticatorData AuthData { get; }
}
