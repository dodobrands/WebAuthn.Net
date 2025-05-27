using WebAuthn.Net.Configuration.Options.AttestationTypes;

namespace WebAuthn.Net.Configuration.Options;

/// <summary>
///     Options that define behavior when working with different <a href="https://www.w3.org/TR/webauthn-3/#sctn-attestation-types">attestation types</a>.
/// </summary>
public class AttestationTypeOptions
{
    /// <summary>
    ///     Options that define behavior when working with the <a href="https://www.w3.org/TR/webauthn-3/#none">"None" attestation type</a>.
    /// </summary>
    public NoneAttestationTypeOptions None { get; set; } = new();

    /// <summary>
    ///     Options that define behavior when working with the <a href="https://www.w3.org/TR/webauthn-3/#self-attestation">"Self" attestation type</a>.
    /// </summary>
    public SelfAttestationOptions Self { get; set; } = new();
}
