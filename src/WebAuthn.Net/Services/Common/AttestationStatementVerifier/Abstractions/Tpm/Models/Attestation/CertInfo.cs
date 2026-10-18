namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>10.11.12 TPMS_ATTEST</para>
///     <para>This structure is used on each TPM-generated signed structure. The signature is over this structure.</para>
///     <para>When the structure is signed by a key in the Storage hierarchy, the values of clockInfo.resetCount, clockInfo.restartCount, and firmwareVersion are obfuscated with a per-key obfuscation value.</para>
///     <para>The reference implementation obfuscates these values whenever the signing key is not in the Endorsement or Platform hierarchy (Part 1, 28.3 and 33.7; Part 3, 18.1). WebAuthn ignores qualifiedSigner, clockInfo and firmwareVersion.</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf">TPM 2.0 Library - Part 2: Structures, Version 185, March 12, 2026</a>
///     </para>
/// </remarks>
public class CertInfo
{
    /// <summary>
    ///     Constructs <see cref="CertInfo" />.
    /// </summary>
    /// <param name="qualifiedSigner">Qualified Name of the signing key. An Empty Buffer for an anonymous (ECDAA) signing scheme; TPM_RH_NULL (size 4) when signed with the NULL key. Ignored by WebAuthn.</param>
    /// <param name="extraData">External information supplied by caller.</param>
    /// <param name="clock">
    ///     <para>10.11.12 TPMS_ATTEST - clockInfo.</para>
    ///     <para>10.10.1 TPMS_CLOCK_INFO - clock (UINT64).</para>
    ///     <para>Time value in milliseconds that advances while the TPM is powered.</para>
    /// </param>
    /// <param name="resetCount">
    ///     <para>10.11.12 TPMS_ATTEST - clockInfo.</para>
    ///     <para>10.10.1 TPMS_CLOCK_INFO - resetCount (UINT32).</para>
    ///     <para>Number of occurrences of TPM Reset since the last TPM2_Clear().</para>
    /// </param>
    /// <param name="restartCount">
    ///     <para>10.11.12 TPMS_ATTEST - clockInfo.</para>
    ///     <para>10.10.1 TPMS_CLOCK_INFO - restartCount (UINT32).</para>
    ///     <para>Number of times that TPM2_Shutdown() or _TPM_Hash_Start have occurred since the last TPM Reset or TPM2_Clear().</para>
    /// </param>
    /// <param name="safe">
    ///     <para>10.11.12 TPMS_ATTEST - clockInfo.</para>
    ///     <para>10.10.1 TPMS_CLOCK_INFO - safe (TPMI_YES_NO).</para>
    ///     <para><see langword="true" /> (YES) when no value of Clock greater than the current value of Clock has been previously reported by the TPM; set to YES on TPM2_Clear().</para>
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
    ///     <para>Qualified Name of the signing key.</para>
    ///     <para>An Empty Buffer for an anonymous (ECDAA) signing scheme; TPM_RH_NULL (size 4) when signed with the NULL key. Ignored by WebAuthn.</para>
    /// </summary>
    public Tpm2BName QualifiedSigner { get; }

    /// <summary>
    ///     External information supplied by caller.
    /// </summary>
    public byte[] ExtraData { get; }

    /// <summary>
    ///     <para>10.11.12 TPMS_ATTEST - clockInfo.</para>
    ///     <para>10.10.1 TPMS_CLOCK_INFO - clock (UINT64).</para>
    ///     <para>Time value in milliseconds that advances while the TPM is powered.</para>
    /// </summary>
    public ulong Clock { get; }

    /// <summary>
    ///     <para>10.11.12 TPMS_ATTEST - clockInfo.</para>
    ///     <para>10.10.1 TPMS_CLOCK_INFO - resetCount (UINT32).</para>
    ///     <para>Number of occurrences of TPM Reset since the last TPM2_Clear().</para>
    /// </summary>
    public uint ResetCount { get; }

    /// <summary>
    ///     <para>10.11.12 TPMS_ATTEST - clockInfo.</para>
    ///     <para>10.10.1 TPMS_CLOCK_INFO - restartCount (UINT32).</para>
    ///     <para>Number of times that TPM2_Shutdown() or _TPM_Hash_Start have occurred since the last TPM Reset or TPM2_Clear().</para>
    /// </summary>
    public uint RestartCount { get; }

    /// <summary>
    ///     <para>10.11.12 TPMS_ATTEST - clockInfo.</para>
    ///     <para>10.10.1 TPMS_CLOCK_INFO - safe (TPMI_YES_NO).</para>
    ///     <para><see langword="true" /> (YES) when no value of Clock greater than the current value of Clock has been previously reported by the TPM; set to YES on TPM2_Clear().</para>
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
