namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     The TPM device attributes (TPMManufacturer, TPMModel and TPMVersion) decoded from the directoryName of the Subject Alternative Name extension of the AIK certificate used for a
///     <a href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">TPM attestation statement</a>.
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://cdn.trustedcomputinggroup.org/production/TCG_EK_Credential_Profile_for_TPM_Family_2_0_Level_0_Version_2_7_Pub_cafa3d55b0.pdf">TCG EK Credential Profile for TPM Family 2.0, Level 0, Version 2.7 (2026-03-16, PUBLISHED)</a>,
///         §3.2.9 "Subject Alternative Name" and §3.1.2 "TPM Device Attributes".
///     </para>
///     <para>WebAuthn Level 3 §8.3.1 cites Version 2.5 Revision 2 of the profile; the Subject Alternative Name requirements are unchanged.</para>
/// </remarks>
public class AikCertSubjectAlternativeName
{
    /// <summary>
    ///     Constructs <see cref="AikCertSubjectAlternativeName" />.
    /// </summary>
    /// <param name="tpmManufacturer">The manufacturer of the TPM module (TPMManufacturer, OID 2.23.133.2.1): "id:" followed by the 4-byte TCG vendor ID as 8 uppercase hexadecimal digits, e.g. "id:414D4400".</param>
    /// <param name="tpmPartNumber">The part number of the TPM module (TPMModel, OID 2.23.133.2.2): a vendor-specific string, e.g. "AMD".</param>
    /// <param name="tpmFirmwareVersion">The firmware version of the TPM module (TPMVersion, OID 2.23.133.2.3): "id:" followed by TPM_PT_FIRMWARE_VERSION_1 as 8 uppercase hexadecimal digits, e.g. "id:00030001".</param>
    public AikCertSubjectAlternativeName(string tpmManufacturer, string tpmPartNumber, string tpmFirmwareVersion)
    {
        TpmManufacturer = tpmManufacturer;
        TpmPartNumber = tpmPartNumber;
        TpmFirmwareVersion = tpmFirmwareVersion;
    }

    /// <summary>
    ///     The manufacturer of the TPM module (TPMManufacturer, OID 2.23.133.2.1): "id:" followed by the 4-byte TCG vendor ID as 8 uppercase hexadecimal digits, e.g. "id:414D4400".
    /// </summary>
    public string TpmManufacturer { get; }

    /// <summary>
    ///     The part number of the TPM module (TPMModel, OID 2.23.133.2.2): a vendor-specific string, e.g. "AMD".
    /// </summary>
    public string TpmPartNumber { get; }

    /// <summary>
    ///     The firmware version of the TPM module (TPMVersion, OID 2.23.133.2.3): "id:" followed by TPM_PT_FIRMWARE_VERSION_1 as 8 uppercase hexadecimal digits, e.g. "id:00030001".
    /// </summary>
    public string TpmFirmwareVersion { get; }
}
