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
    ///     Rejected: the aaguid of the authenticator data is not zero and differs from the aaguid of the id-fido-gen-ce-aaguid extension of the attestation certificate.
    ///     The FIDO U2F attestation signature doesn't cover the aaguid of the authenticator data, so only the extension attests the authenticator model, and the authenticator data claims another one.
    /// </summary>
    public const string AuthenticatorDataAaguidMismatch = "authdata.aaguid_mismatch";
}
