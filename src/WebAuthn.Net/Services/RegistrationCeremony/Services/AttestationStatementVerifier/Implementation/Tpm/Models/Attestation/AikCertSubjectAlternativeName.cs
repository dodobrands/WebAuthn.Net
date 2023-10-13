namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation;

public class AikCertSubjectAlternativeName
{
    public AikCertSubjectAlternativeName(string tpmManufacturer, string tpmPartNumber, string tpmFirmwareVersion)
    {
        TpmManufacturer = tpmManufacturer;
        TpmPartNumber = tpmPartNumber;
        TpmFirmwareVersion = tpmFirmwareVersion;
    }

    public string TpmManufacturer { get; }
    public string TpmPartNumber { get; }
    public string TpmFirmwareVersion { get; }
}
