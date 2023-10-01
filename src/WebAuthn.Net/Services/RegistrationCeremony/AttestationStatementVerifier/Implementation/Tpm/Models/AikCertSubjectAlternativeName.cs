namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.Tpm.Models;

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
