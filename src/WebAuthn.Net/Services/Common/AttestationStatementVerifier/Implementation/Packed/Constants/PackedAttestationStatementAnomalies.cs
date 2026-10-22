namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Packed.Constants;

/// <summary>
///     The anomalies that <see cref="AttestationStatementDecoder.Implementation.AttestationStatements.DefaultPackedAttestationStatementDecoder" /> reports with a Warning log entry and the
///     <c>webauthn.reg.attestation.anomalies</c> counter (<see cref="Metrics.IRegistrationCeremonyCounters.IncrementAttestationStatementAnomaly" />, tag <c>fmt</c> = <see cref="Format" />).
/// </summary>
public static class PackedAttestationStatementAnomalies
{
    /// <summary>
    ///     The attestation statement format identifier of the Packed attestation statement format.
    /// </summary>
    public const string Format = "packed";

    /// <summary>
    ///     Tolerated: the 'attStmt' map contains members that are not defined by the packedStmtFormat syntax (for example, the 'ecdaaKeyId' of WebAuthn Level 1). Nothing in the verification procedure
    ///     uses such a member, so it is ignored. Counted once per attestation statement, however many such members it contains.
    /// </summary>
    public const string AttStmtMemberOutsideSyntax = "attstmt.member_outside_syntax";
}
