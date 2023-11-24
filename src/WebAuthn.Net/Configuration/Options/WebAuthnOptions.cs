namespace WebAuthn.Net.Configuration.Options;

/// <summary>
///     Global options for WebAuthn.Net.
/// </summary>
public class WebAuthnOptions
{
    /// <summary>
    ///     Options that define behavior when working with various <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-defined-attestation-formats">formats of attestation statements</a>.
    /// </summary>
    public AttestationStatementOptions AttestationStatements { get; set; } = new();

    /// <summary>
    ///     Options that define behavior when working with different <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation-types">attestation types</a>.
    /// </summary>
    public AttestationTypeOptions AttestationTypes { get; set; } = new();

    /// <summary>
    ///     Options that define the behavior of X509v3 certificate chain validation.
    /// </summary>
    public X509ChainValidationOptions X509ChainValidation { get; set; } = new();

    /// <summary>
    ///     Options that define behavior when working with FIDO Metadata Service.
    /// </summary>
    public FidoMetadataOptions FidoMetadata { get; set; } = new();

    /// <summary>
    ///     Options that define the behavior of the authentication ceremony.
    /// </summary>
    public AuthenticationCeremonyOptions AuthenticationCeremony { get; set; } = new();

    /// <summary>
    ///     Options that define the behavior of the registration ceremony.
    /// </summary>
    public RegistrationCeremonyOptions RegistrationCeremony { get; set; } = new();
}
