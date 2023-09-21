using System;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Implementation.AttestationStatements;

public class DefaultNoneAttestationStatementDecoder : INoneAttestationStatementDecoder
{
    public Result<NoneAttestationStatement> Decode(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        var dict = attStmt.Value;
        if (dict.Count > 0)
        {
            return Result<NoneAttestationStatement>.Failed("The attStmt for the 'none' type should consist of an empty CBOR map.");
        }

        return Result<NoneAttestationStatement>.Success(new());
    }
}
