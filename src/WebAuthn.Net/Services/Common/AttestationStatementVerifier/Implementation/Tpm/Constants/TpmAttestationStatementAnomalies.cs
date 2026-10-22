namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Constants;

/// <summary>
///     The anomalies that <see cref="AttestationStatementDecoder.Implementation.AttestationStatements.DefaultTpmAttestationStatementDecoder" /> and <see cref="DefaultTpmAttestationStatementVerifier{TContext}" /> report with a Warning log entry and the
///     <c>webauthn.reg.attestation.anomalies</c> counter (<see cref="Metrics.IRegistrationCeremonyCounters.IncrementAttestationStatementAnomaly" />, tag <c>fmt</c> = <see cref="Format" />).
/// </summary>
/// <remarks>
///     <para>
///         Tolerated anomalies are deviations from the specifications that the verifier accepts on purpose (usually because the TCG reference implementation or deployed authenticators behave that way);
///         rejected anomalies are values that are valid according to the specifications but unknown to the library, so the attestation statement cannot be verified until the library is updated.
///     </para>
/// </remarks>
public static class TpmAttestationStatementAnomalies
{
    /// <summary>
    ///     The attestation statement format identifier of the TPM attestation statement format.
    /// </summary>
    public const string Format = "tpm";

    /// <summary>
    ///     Tolerated: the 'attStmt' map contains members that are not defined by the tpmStmtFormat syntax (for example, the 'ecdaaKeyId' of WebAuthn Level 1). Nothing in the verification procedure
    ///     uses such a member, so it is ignored. Counted once per attestation statement, however many such members it contains.
    /// </summary>
    public const string AttStmtMemberOutsideSyntax = "attstmt.member_outside_syntax";

    /// <summary>
    ///     Tolerated: bit 3 of the objectAttributes (TPMA_OBJECT) of the pubArea is SET. Every published revision of TPM 2.0 Library Part 2 reserves it ("shall be zero"),
    ///     but the TCG reference implementation does not (a stale TPMA_OBJECT_fixedFirmware definition), so a TPM derived from it may create keys with this bit SET.
    /// </summary>
    public const string PubAreaReservedBit3 = "pubarea.reserved_bit_3";

    /// <summary>
    ///     Rejected: the nameAlg of the pubArea is a valid TPMI_ALG_HASH value, but this library cannot compute that hash algorithm, so the Name in certInfo cannot be verified.
    /// </summary>
    public const string PubAreaNameAlgNotSupported = "pubarea.name_alg_not_supported";

    /// <summary>
    ///     Tolerated by default, rejected when <see cref="DefaultTpmAttestationStatementVerifier{TContext}.IsTpmBoundCredentialKeyRequired" /> says so: the credential key of the pubArea is not bound to the TPM -
    ///     at least one of fixedTPM, fixedParent and sensitiveDataOrigin is CLEAR in its objectAttributes (TPM 2.0 Library Part 2 v185 §8.3.3.2, §8.3.3.4 and §8.3.3.5).
    ///     That is what a key imported with TPM2_Import() or loaded with TPM2_LoadExternal() looks like, so a copy of its private part may exist outside the TPM.
    /// </summary>
    public const string PubAreaKeyNotTpmBound = "pubarea.key_not_tpm_bound";

    /// <summary>
    ///     Tolerated: the nameAlg of the pubArea is TPM_ALG_SHA1 (deprecated since version 184 of the TPM 2.0 Library, Part 0 v185 §3.1.1.2), so the Name that binds certInfo to the pubArea is a SHA-1 digest.
    ///     (An attestation signature with 'alg' RS1 is not an anomaly: Windows Hello signs certInfo with RS1 for every credential key type.)
    /// </summary>
    public const string PubAreaNameAlgSha1 = "pubarea.name_alg_sha1";

    /// <summary>
    ///     Rejected: the TPMManufacturer attribute of the AIK certificate is not one of the vendor identifiers that this library knows (its copy of the TCG TPM Vendor ID Registry).
    /// </summary>
    public const string AikCertificateManufacturerUnknown = "aik.manufacturer_unknown";

    /// <summary>
    ///     Tolerated: the TPMManufacturer attribute of the AIK certificate is a known vendor identifier, but its hexadecimal digits are not uppercase
    ///     (TCG EK Credential Profile 2.7, §3.1.2: "the characters 0-9 and A-F").
    /// </summary>
    public const string AikCertificateManufacturerNotCanonical = "aik.manufacturer_not_canonical";

    /// <summary>
    ///     Tolerated: the Subject Alternative Name extension of the AIK certificate is not critical although its subject is empty
    ///     (TCG EK Credential Profile 2.7, §3.2.9 and RFC 5280, §4.2.1.6: the extension MUST be critical if the subject is empty).
    /// </summary>
    public const string AikCertificateSanNotCritical = "aik.san_not_critical";

    /// <summary>
    ///     Tolerated: the value of the Subject Alternative Name extension of the AIK certificate is a bare RDNSequence (the layout of the certificate example of the TCG EK Credential Profile)
    ///     instead of GeneralNames with a directoryName.
    /// </summary>
    public const string AikCertificateSanWithoutGeneralNames = "aik.san_without_general_names";

    /// <summary>
    ///     Tolerated: the Subject Alternative Name extension of the AIK certificate contains a HardwareModuleName (RFC 4108), which WebAuthn says SHOULD NOT be placed there; it is ignored.
    /// </summary>
    public const string AikCertificateSanHardwareModuleName = "aik.san_hardware_module_name";

    /// <summary>
    ///     Tolerated: the Subject Alternative Name extension of the AIK certificate contains the same TPM device attribute (TPMManufacturer, TPMModel or TPMVersion) more than once, with the same value.
    /// </summary>
    public const string AikCertificateSanDuplicateAttribute = "aik.san_duplicate_attribute";
}
