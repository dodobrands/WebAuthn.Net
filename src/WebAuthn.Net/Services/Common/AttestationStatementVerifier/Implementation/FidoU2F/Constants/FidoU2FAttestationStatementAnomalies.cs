namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.FidoU2F.Constants;

/// <summary>
///     The anomalies that <see cref="DefaultFidoU2FAttestationStatementVerifier{TContext}" /> reports with a Warning log entry and the
///     <c>webauthn.reg.attestation.anomalies</c> counter (<see cref="Metrics.IRegistrationCeremonyCounters.IncrementAttestationStatementAnomaly" />, tag <c>fmt</c> = <see cref="Format" />).
/// </summary>
public static class FidoU2FAttestationStatementAnomalies
{
    /// <summary>
    ///     The attestation statement format identifier of the FIDO U2F attestation statement format.
    /// </summary>
    public const string Format = "fido-u2f";

    /// <summary>
    ///     Rejected: the aaguid of the authenticator data is not zero.
    ///     The client builds the authenticator data of a FIDO U2F attestation with an aaguid of all zeros (FIDO CTAP §10.2), and the FIDO U2F attestation signature doesn't cover it, so a non-zero aaguid is attested by nothing.
    /// </summary>
    public const string AuthenticatorDataAaguidNotZero = "authdata.aaguid_not_zero";
}
