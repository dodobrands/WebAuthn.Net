namespace WebAuthn.Net.Configuration.Options.AttestationTypes;

/// <summary>
///     Options that define behavior when working with the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#none">"None" attestation type</a>.
/// </summary>
public class NoneAttestationTypeOptions
{
    /// <summary>
    ///     A flag controlling whether the Relying Party policy accepts the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#none">"None" attestation type</a>. Defaults to <see langword="true" />, because this is the format returned by Apple starting with iOS 16 regardless of
    ///     the requested attestation format, and also by Google on Android when using Passkeys.
    /// </summary>
    public bool IsAcceptable { get; set; } = true;
}
