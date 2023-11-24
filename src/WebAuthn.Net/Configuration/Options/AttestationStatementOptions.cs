using WebAuthn.Net.Configuration.Options.AttestationStatements;

namespace WebAuthn.Net.Configuration.Options;

/// <summary>
///     Options that define behavior when working with various formats of attestation statements.
/// </summary>
public class AttestationStatementOptions
{
    /// <summary>
    ///     Options that define behavior when working with <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-key-attestation">"Android Key" attestation format</a>.
    /// </summary>
    public AndroidKeyAttestationStatementOptions AndroidKey { get; set; } = new();
}
