namespace WebAuthn.Net.Configuration.Options.AttestationStatements;

/// <summary>
///     Options that define behavior when working with <a href="https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation">"Android Key" attestation format</a>.
/// </summary>
public class AndroidKeyAttestationStatementOptions
{
    /// <summary>
    ///     A flag controlling if the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> wants to accept only keys from a trusted execution environment (TEE). Defaults to <see langword="true" />.
    /// </summary>
    /// <remarks>
    ///     When it is <see langword="true" />, the purpose and the origin of the key are taken only from the teeEnforced (hardwareEnforced) authorization list of the attestation certificate extension data,
    ///     and both its attestationSecurityLevel and keyMintSecurityLevel must be TrustedEnvironment or StrongBox (a key in StrongBox is accepted as well).
    ///     When it is <see langword="false" />, the union of the teeEnforced and softwareEnforced authorization lists is used, so keys of the software keystore are accepted too.
    /// </remarks>
    public bool AcceptKeysOnlyFromTrustedExecutionEnvironment { get; set; } = true;
}
