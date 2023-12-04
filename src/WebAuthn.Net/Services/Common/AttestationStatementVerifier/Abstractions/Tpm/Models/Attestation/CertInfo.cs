namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     The TPMS_ATTEST structure over which the above signature was computed, as specified in <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">[TPMv2-Part2]</a> section 10.12.12.
/// </summary>
public class CertInfo
{
    public CertInfo(
        Tpm2BName qualifiedSigner,
        byte[] extraData,
        ulong clock,
        uint resetCount,
        uint restartCount,
        bool safe,
        ulong firmwareVersion,
        Attested attested)
    {
        QualifiedSigner = qualifiedSigner;
        ExtraData = extraData;
        Clock = clock;
        ResetCount = resetCount;
        RestartCount = restartCount;
        Safe = safe;
        FirmwareVersion = firmwareVersion;
        Attested = attested;
    }

    public Tpm2BName QualifiedSigner { get; }
    public byte[] ExtraData { get; }
    public ulong Clock { get; }
    public uint ResetCount { get; }
    public uint RestartCount { get; }
    public bool Safe { get; }
    public ulong FirmwareVersion { get; }
    public Attested Attested { get; }
}
