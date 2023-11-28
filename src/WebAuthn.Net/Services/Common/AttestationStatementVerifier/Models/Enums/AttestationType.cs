namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;

/// <summary>
///     Attestation type
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation-types">Web Authentication: An API for accessing Public Key Credentials Level 3 - §6.5.4. Attestation Types</a>
/// </remarks>
public enum AttestationType
{
    /// <summary>
    ///     <para>
    ///         In the case of basic attestation <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#biblio-uafprotocol">[UAFProtocol]</a>, the authenticator's <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-key-pair">attestation key pair</a> is
    ///         specific to an authenticator "model", i.e., a "batch" of authenticators. Thus, authenticators of the same, or similar, model often share the same <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-key-pair">attestation key pair</a>. See
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation-privacy">§14.4.1 Attestation Privacy</a> for further information.
    ///     </para>
    ///     <para><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#basic-attestation">Basic attestation</a> is also referred to as <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#ref-for-batch-attestation">batch attestation</a>.</para>
    /// </summary>
    Basic = 0,

    /// <summary>
    ///     In the case of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#self-attestation">self attestation</a>, also known as surrogate basic attestation <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#biblio-uafprotocol">[UAFProtocol]</a>, the Authenticator
    ///     does not have any specific <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-key-pair">attestation key pair</a>. Instead it uses the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-private-key">credential private key</a> to create
    ///     the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-signature">attestation signature</a>. Authenticators without meaningful protection measures for an
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-private-key">attestation private key</a> typically use this attestation type.
    /// </summary>
    Self = 1,

    /// <summary>
    ///     In this case, an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> is based on a Trusted Platform Module (TPM) and holds an authenticator-specific "endorsement key" (EK). This key is used to securely communicate with a trusted third
    ///     party, the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-ca">Attestation CA</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#biblio-tcg-cmcprofile-aikcertenroll">[TCG-CMCProfile-AIKCertEnroll]</a> (formerly known as a "Privacy CA").
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> can generate multiple attestation identity key pairs (AIK) and requests an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-ca">Attestation CA</a> to issue
    ///     an AIK certificate for each. Using this approach, such an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> can limit the exposure of the EK (which is a global correlation handle) to Attestation CA(s). AIKs can be requested for each
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator-generated</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">public key credential</a> individually, and conveyed to
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> as <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-certificate">attestation certificates</a>.
    /// </summary>
    /// <remarks>
    ///     <para>This concept typically leads to multiple attestation certificates. The attestation certificate requested most recently is called "active".</para>
    ///     <para>
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">Attestation statements</a> conveying <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation">attestations</a> of
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-type">type</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attca">AttCA</a> or <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#anonca">AnonCA</a> use the same data
    ///         structure as those of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-type">type</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#basic">Basic</a>, so the three attestation types are, in general, distinguishable only with externally
    ///         provided knowledge regarding the contents of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-certificate">attestation certificates</a> conveyed in the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a>.
    ///     </para>
    /// </remarks>
    AttCa = 2,

    /// <summary>
    ///     In this case, the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> uses an <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#anonymization-ca">Anonymization CA</a> which dynamically generates
    ///     <a href="https://w3c.github.io/webappsec-credential-management/#concept-credential">per-credential attestation certificates</a> such that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statements</a> presented to
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> do not provide uniquely identifiable information, e.g., that might be used for tracking purposes.
    /// </summary>
    /// <remarks>
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">Attestation statements</a> conveying <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation">attestations</a> of
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-type">type</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attca">AttCA</a> or <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#anonca">AnonCA</a> use the same data structure
    ///     as those of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-type">type</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#basic">Basic</a>, so the three attestation types are, in general, distinguishable only with externally provided
    ///     knowledge regarding the contents of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-certificate">attestation certificates</a> conveyed in the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a>.
    /// </remarks>
    AnonCa = 3,

    /// <summary>
    ///     In this case, no attestation information is available. See also <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-none-attestation">§8.7 None Attestation Statement Format</a>.
    /// </summary>
    None = 4
}
