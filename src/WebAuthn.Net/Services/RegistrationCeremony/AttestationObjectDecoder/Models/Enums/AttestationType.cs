namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.Enums;

/// <summary>
///     Attestation Types
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#sctn-attestation-types">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 6.5.3. Attestation Types</a>
/// </remarks>
public enum AttestationType
{
    /// <summary>
    ///     In the case of basic attestation <a href="https://www.w3.org/TR/webauthn-3/#biblio-uafprotocol">[UAFProtocol]</a>,
    ///     the authenticator’s <a href="https://www.w3.org/TR/webauthn-3/#attestation-key-pair">attestation key pair</a> is specific to an authenticator "model",
    ///     i.e., a "batch" of authenticators. Thus, authenticators of the same, or similar, model often share the same <a href="https://www.w3.org/TR/webauthn-3/#attestation-key-pair">attestation key pair</a>.
    ///     See <a href="https://www.w3.org/TR/webauthn-3/#sctn-attestation-privacy">§ 14.4.1 Attestation Privacy</a> for further information.
    /// </summary>
    Basic = 0,

    /// <summary>
    ///     In the case of <a href="https://www.w3.org/TR/webauthn-3/#self-attestation">self attestation</a>, also known as surrogate basic attestation <a href="https://www.w3.org/TR/webauthn-3/#biblio-uafprotocol">[UAFProtocol]</a>,
    ///     the Authenticator does not have any specific <a href="https://www.w3.org/TR/webauthn-3/#attestation-key-pair">attestation key pair</a>.
    ///     Instead it uses the <a href="https://www.w3.org/TR/webauthn-3/#credential-private-key">credential private key</a>
    ///     to create the <a href="https://www.w3.org/TR/webauthn-3/#attestation-signature">attestation signature</a>.
    ///     Authenticators without meaningful protection measures for an <a href="https://www.w3.org/TR/webauthn-3/#attestation-private-key">attestation private key</a> typically use this attestation type.
    /// </summary>
    Self = 1,

    /// <summary>
    ///     In this case, an <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> is based on a Trusted Platform Module (TPM) and
    ///     holds an authenticator-specific "endorsement key" (EK). This key is used to securely communicate with a trusted third party,
    ///     the <a href="https://www.w3.org/TR/webauthn-3/#attestation-ca">Attestation CA</a> <a href="https://www.w3.org/TR/webauthn-3/#biblio-tcg-cmcprofile-aikcertenroll">[TCG-CMCProfile-AIKCertEnroll]</a>
    ///     (formerly known as a "Privacy CA"). The <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> can generate multiple attestation identity key pairs (AIK)
    ///     and requests an <a href="https://www.w3.org/TR/webauthn-3/#attestation-ca">Attestation CA</a> to issue an AIK certificate for each.
    ///     Using this approach, such an <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> can limit the exposure of the EK (which is a global correlation handle)
    ///     to Attestation CA(s). AIKs can be requested for each <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a>-generated
    ///     <a href="https://www.w3.org/TR/webauthn-3/#public-key-credential">public key credential</a> individually,
    ///     and conveyed to <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a> as
    ///     <a href="https://www.w3.org/TR/webauthn-3/#attestation-certificate">attestation certificates</a>.
    /// </summary>
    /// <remarks>
    ///     Note: This concept typically leads to multiple attestation certificates. The attestation certificate requested most recently is called "active".
    /// </remarks>
    AttCa = 2,

    /// <summary>
    ///     In this case, the <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> uses an <a href="https://www.w3.org/TR/webauthn-3/#anonymization-ca">Anonymization CA</a>
    ///     which dynamically generates <a href="https://www.w3.org/TR/credential-management-1/#concept-credential">per-credential attestation certificates</a>
    ///     such that the <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement">attestation statements</a> presented to <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a>
    ///     do not provide uniquely identifiable information, e.g., that might be used for tracking purposes.
    /// </summary>
    /// <remarks>
    ///     Note: <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement">Attestation statements</a> conveying <a href="https://www.w3.org/TR/webauthn-3/#attestation">attestations</a>
    ///     of <a href="https://www.w3.org/TR/webauthn-3/#attestation-type">type</a> <a href="https://www.w3.org/TR/webauthn-3/#attca">AttCA</a> or <a href="https://www.w3.org/TR/webauthn-3/#anonca">AnonCA</a>
    ///     use the same data structure as those of <a href="https://www.w3.org/TR/webauthn-3/#attestation-type">type</a> <a href="https://www.w3.org/TR/webauthn-3/#basic">Basic</a>,
    ///     so the three attestation types are, in general, distinguishable only with externally provided knowledge regarding the contents
    ///     of the <a href="https://www.w3.org/TR/webauthn-3/#attestation-certificate">attestation certificates</a> conveyed in the <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement">attestation statement</a>.
    /// </remarks>
    AnonCa = 3,

    /// <summary>
    ///     In this case, no attestation information is available. See also <a href="https://www.w3.org/TR/webauthn-3/#sctn-none-attestation">§ 8.7 None Attestation Statement Format</a>
    /// </summary>
    None = 4
}
