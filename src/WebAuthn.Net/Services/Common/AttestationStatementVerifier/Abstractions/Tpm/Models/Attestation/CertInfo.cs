namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>10.12.12 TPMS_ATTEST</para>
///     <para>This structure is used on each TPM-generated signed structure. The signature is over this structure.</para>
///     <para>When the structure is signed by a key in the Storage hierarchy, the values of clockInfo.resetCount, clockInfo.restartCount, and firmwareVersion are obfuscated with a per-key obfuscation value.</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
///     </para>
/// </remarks>
public class CertInfo
{
    /// <summary>
    ///     Constructs <see cref="CertInfo" />.
    /// </summary>
    /// <param name="qualifiedSigner">Qualified Name of the signing key.</param>
    /// <param name="extraData">External information supplied by caller.</param>
    /// <param name="clock">
    ///     <para>10.12.12 TPMS_ATTEST - clockInfo.</para>
    ///     <para>10.11.1 TPMS_CLOCK_INFO - clock (UINT64).</para>
    ///     <para>Time value in milliseconds that advances while the TPM is powered.</para>
    /// </param>
    /// <param name="resetCount">
    ///     <para>10.12.12 TPMS_ATTEST - clockInfo.</para>
    ///     <para>10.11.1 TPMS_CLOCK_INFO - resetCount (UINT32).</para>
    ///     <para>Number of occurrences of TPM Reset since the last TPM2_Clear().</para>
    /// </param>
    /// <param name="restartCount">
    ///     <para>10.12.12 TPMS_ATTEST - clockInfo.</para>
    ///     <para>10.11.1 TPMS_CLOCK_INFO - restartCount (UINT32).</para>
    ///     <para>Number of occurrences of TPM Reset since the last TPM2_Clear().</para>
    /// </param>
    /// <param name="safe">
    ///     <para>10.12.12 TPMS_ATTEST - clockInfo.</para>
    ///     <para>10.11.1 TPMS_CLOCK_INFO - safe (TPMI_YES_NO).</para>
    ///     <para><see langword="false" /> (no) value of Clock greater than the current value of Clock has been previously reported by the TPM. </para>
    ///     <para>Set to <see langword="true" /> (yes) on TPM2_Clear().</para>
    /// </param>
    /// <param name="firmwareVersion">TPM-vendor-specific value identifying the version number of the firmware.</param>
    /// <param name="attested">The type-specific attestation information.</param>
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

    /// <summary>
    ///     Qualified Name of the signing key.
    /// </summary>
    public Tpm2BName QualifiedSigner { get; }

    /// <summary>
    ///     External information supplied by caller.
    /// </summary>
    public byte[] ExtraData { get; }

    /// <summary>
    ///     <para>10.12.12 TPMS_ATTEST - clockInfo.</para>
    ///     <para>10.11.1 TPMS_CLOCK_INFO - clock (UINT64).</para>
    ///     <para>Time value in milliseconds that advances while the TPM is powered.</para>
    /// </summary>
    public ulong Clock { get; }

    /// <summary>
    ///     <para>10.12.12 TPMS_ATTEST - clockInfo.</para>
    ///     <para>10.11.1 TPMS_CLOCK_INFO - resetCount (UINT32).</para>
    ///     <para>Number of occurrences of TPM Reset since the last TPM2_Clear().</para>
    /// </summary>
    public uint ResetCount { get; }

    /// <summary>
    ///     <para>10.12.12 TPMS_ATTEST - clockInfo.</para>
    ///     <para>10.11.1 TPMS_CLOCK_INFO - restartCount (UINT32).</para>
    ///     <para>Number of occurrences of TPM Reset since the last TPM2_Clear().</para>
    /// </summary>
    public uint RestartCount { get; }

    /// <summary>
    ///     <para>10.12.12 TPMS_ATTEST - clockInfo.</para>
    ///     <para>10.11.1 TPMS_CLOCK_INFO - safe (TPMI_YES_NO).</para>
    ///     <para><see langword="false" /> (no) value of Clock greater than the current value of Clock has been previously reported by the TPM. </para>
    ///     <para>Set to <see langword="true" /> (yes) on TPM2_Clear().</para>
    /// </summary>
    public bool Safe { get; }

    /// <summary>
    ///     TPM-vendor-specific value identifying the version number of the firmware.
    /// </summary>
    public ulong FirmwareVersion { get; }

    /// <summary>
    ///     The type-specific attestation information.
    /// </summary>
    public Attested Attested { get; }
}
