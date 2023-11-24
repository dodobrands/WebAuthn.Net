namespace WebAuthn.Net.Configuration.Options.AttestationStatements;

/// <summary>
///     Options that define behavior when working with <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-key-attestation">"Android Key" attestation format</a>.
/// </summary>
public class AndroidKeyAttestationStatementOptions
{
    /// <summary>
    ///     A flag controlling if the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> wants to accept only keys from a trusted execution environment (TEE). Defaults to <see langword="true" />.
    /// </summary>
    public bool AcceptKeysOnlyFromTrustedExecutionEnvironment { get; set; } = true;
}
