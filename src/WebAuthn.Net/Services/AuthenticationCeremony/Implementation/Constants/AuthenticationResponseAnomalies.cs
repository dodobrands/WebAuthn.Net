namespace WebAuthn.Net.Services.AuthenticationCeremony.Implementation.Constants;

/// <summary>
///     The anomalies that <see cref="DefaultAuthenticationCeremonyService{TContext}" /> reports with a Warning log entry and the
///     <c>webauthn.authn.response.anomalies</c> counter (<see cref="Metrics.IAuthenticationCeremonyCounters.IncrementResponseAnomaly" />).
/// </summary>
public static class AuthenticationResponseAnomalies
{
    /// <summary>
    ///     The signature counter of the authenticator data ('authData.signCount') is less than or equal to the one stored in the credential record, although at least one of them is nonzero.
    ///     This is a signal, but not proof, that the authenticator may be cloned (<a href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">WebAuthn Level 3, §7.2, step 22</a>).
    ///     Rejected when <see cref="Configuration.Options.AuthenticationCeremonyOptions.AbortCeremonyWhenSignCountIsLessOrEqualStoredValue" /> is <see langword="true" /> (the default), otherwise tolerated.
    /// </summary>
    public const string SignCountNotIncreased = "sign_count.not_increased";
}
