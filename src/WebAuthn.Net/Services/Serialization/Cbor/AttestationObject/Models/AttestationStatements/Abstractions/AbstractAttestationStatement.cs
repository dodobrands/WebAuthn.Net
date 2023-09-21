namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements.Abstractions;

public abstract class AbstractAttestationStatement
{
    public abstract TResult Accept<TResult>(IAttestationStatementVisitor<TResult> visitor);
}
