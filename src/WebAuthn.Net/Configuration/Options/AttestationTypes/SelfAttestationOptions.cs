namespace WebAuthn.Net.Configuration.Options.AttestationTypes;

/// <summary>
///     Options that define behavior when working with the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#self-attestation">"Self" attestation type</a>.
/// </summary>
public class SelfAttestationOptions
{
    /// <summary>
    ///     A flag controlling whether the Relying Party policy accepts the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#self-attestation">"Self" attestation type</a>. Defaults to <see langword="true" />.
    /// </summary>
    public bool IsAcceptable { get; set; } = true;
}
