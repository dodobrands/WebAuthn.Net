namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements.Abstractions;

public interface IAttestationStatementVisitor<out TResult>
{
    TResult VisitPackedAttestationStatement(PackedAttestationStatement attestationStatement);
    TResult VisitTpmAttestationStatement(TpmAttestationStatement attestationStatement);
    TResult VisitAndroidKeyAttestationStatement(AndroidKeyAttestationStatement attestationStatement);
    TResult VisitAndroidSafetyNetAttestationStatement(AndroidSafetyNetAttestationStatement attestationStatement);
    TResult VisitFidoU2FAttestationStatement(FidoU2FAttestationStatement attestationStatement);
    TResult VisitNoneAttestationStatement(NoneAttestationStatement attestationStatement);
    TResult VisitAppleAnonymousAttestationStatement(AppleAnonymousAttestationStatement attestationStatement);
}
