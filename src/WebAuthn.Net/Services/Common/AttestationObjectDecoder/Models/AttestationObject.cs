using System;
using System.ComponentModel;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

namespace WebAuthn.Net.Services.Common.AttestationObjectDecoder.Models;

public class AttestationObject
{
    public AttestationObject(
        AttestationStatementFormat fmt,
        CborMap attStmt,
        byte[]? authData)
    {
        if (!Enum.IsDefined(typeof(AttestationStatementFormat), fmt))
        {
            throw new InvalidEnumArgumentException(nameof(fmt), (int) fmt, typeof(AttestationStatementFormat));
        }

        ArgumentNullException.ThrowIfNull(attStmt);
        Fmt = fmt;
        AttStmt = attStmt;
        AuthData = authData;
    }

    public AttestationStatementFormat Fmt { get; }

    public CborMap AttStmt { get; }

    public byte[]? AuthData { get; }
}
