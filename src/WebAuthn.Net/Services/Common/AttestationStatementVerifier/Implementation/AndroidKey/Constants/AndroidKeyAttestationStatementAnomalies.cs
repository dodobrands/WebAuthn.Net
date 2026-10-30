namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidKey.Constants;

/// <summary>
///     The anomalies that <see cref="AttestationStatementDecoder.Implementation.AttestationStatements.DefaultAndroidKeyAttestationStatementDecoder" /> reports with a Warning log entry and the
///     <c>webauthn.reg.attestation.anomalies</c> counter (<see cref="Metrics.IRegistrationCeremonyCounters.IncrementAttestationStatementAnomaly" />, tag <c>fmt</c> = <see cref="Format" />).
/// </summary>
public static class AndroidKeyAttestationStatementAnomalies
{
    /// <summary>
    ///     The attestation statement format identifier of the Android Key attestation statement format.
    /// </summary>
    public const string Format = "android-key";

    /// <summary>
    ///     Tolerated: the 'attStmt' map contains members that are not defined by the androidStmtFormat syntax. Nothing in the verification procedure uses such a member, so it is ignored.
    ///     Counted once per attestation statement, however many such members it contains.
    /// </summary>
    public const string AttStmtMemberOutsideSyntax = "attstmt.member_outside_syntax";
}
