namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     The decoded ASN.1 extension of the X509v3 certificate, which contains data about the TPM module.
/// </summary>
/// <remarks>
///     <a href="https://trustedcomputinggroup.org/resource/http-trustedcomputinggroup-org-wp-content-uploads-tcg-ek-credential-profile-v-2-5-r2_published-pdf/">TCG EK Credential Profile for TPM Family 2.0</a>
/// </remarks>
public class AikCertSubjectAlternativeName
{
    /// <summary>
    ///     Constructs <see cref="AikCertSubjectAlternativeName" />.
    /// </summary>
    /// <param name="tpmManufacturer">The manufacturer of the TPM module.</param>
    /// <param name="tpmPartNumber">The part number of the TPM module.</param>
    /// <param name="tpmFirmwareVersion">The firmware version of the TPM module.</param>
    public AikCertSubjectAlternativeName(string tpmManufacturer, string tpmPartNumber, string tpmFirmwareVersion)
    {
        TpmManufacturer = tpmManufacturer;
        TpmPartNumber = tpmPartNumber;
        TpmFirmwareVersion = tpmFirmwareVersion;
    }

    /// <summary>
    ///     The manufacturer of the TPM module.
    /// </summary>
    public string TpmManufacturer { get; }

    /// <summary>
    ///     The part number of the TPM module.
    /// </summary>
    public string TpmPartNumber { get; }

    /// <summary>
    ///     The firmware version of the TPM module.
    /// </summary>
    public string TpmFirmwareVersion { get; }
}
