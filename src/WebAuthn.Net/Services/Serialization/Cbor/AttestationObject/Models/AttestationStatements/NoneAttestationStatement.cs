using System;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;

public class NoneAttestationStatement : AbstractAttestationStatement
{
    public override TResult Accept<TResult>(IAttestationStatementVisitor<TResult> visitor)
    {
        ArgumentNullException.ThrowIfNull(visitor);
        return visitor.VisitNoneAttestationStatement(this);
    }
}
