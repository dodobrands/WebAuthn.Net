using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Constants;

/// <summary>
///     TPM manufacturers mapped to their TPMManufacturer identifiers: "id:" followed by the 4-byte TCG vendor ID as 8 uppercase hexadecimal digits (TCG EK Credential Profile 2.7 §3.1.2).
/// </summary>
/// <remarks>
///     <para>TCG TPM Vendor ID Registry, Family 1.2 and 2.0, Version 1.08 (2026-07-20, PUBLISHED), Table 2.</para>
///     <para>
///         <a href="https://www.trustedcomputinggroup.org/resources/documents/vendor-id-registry">https://www.trustedcomputinggroup.org/resources/documents/vendor-id-registry</a>
///     </para>
///     <para>
///         <a href="https://cdn.trustedcomputinggroup.org/production/TCG_TPM_Vendor_ID_Registry_V1_08_pub_e09a1a8dab.pdf">https://cdn.trustedcomputinggroup.org/production/TCG_TPM_Vendor_ID_Registry_V1_08_pub_e09a1a8dab.pdf</a>
///     </para>
///     <para>The simulator and test identifiers of Table 3 (SIM0-SIM7, TST0-TST7) are intentionally absent: the registry states that they are not intended for use in production.</para>
/// </remarks>
[SuppressMessage("ReSharper", "InconsistentNaming")]
public static class TpmManufacturers
{
    /// <summary>
    ///     Advanced Micro Devices, Inc.
    /// </summary>
    public const string AMD = "id:414D4400";

    /// <summary>
    ///     Ant Group
    /// </summary>
    public const string AntGroup = "id:414E5400";

    /// <summary>
    ///     Arm
    /// </summary>
    public const string Arm = "id:41524D00";

    /// <summary>
    ///     Atmel
    /// </summary>
    public const string Atmel = "id:41544D4C";

    /// <summary>
    ///     Broadcom
    /// </summary>
    public const string Broadcom = "id:4252434D";

    /// <summary>
    ///     Cisco
    /// </summary>
    public const string Cisco = "id:4353434F";

    /// <summary>
    ///     FlySlice Technologies
    /// </summary>
    public const string FlysliceTechnologies = "id:464C5953";

    /// <summary>
    ///     Rockchip
    /// </summary>
    public const string FuzhouRockchip = "id:524F4343";

    /// <summary>
    ///     Google
    /// </summary>
    public const string Google = "id:474F4F47";

    /// <summary>
    ///     Hewlett-Packard Company (HP Inc.)
    /// </summary>
    public const string HPI = "id:48504900";

    /// <summary>
    ///     Hewlett Packard Enterprise
    /// </summary>
    public const string HPE = "id:48504500";

    /// <summary>
    ///     Huawei
    /// </summary>
    public const string Huawei = "id:48495349";

    /// <summary>
    ///     IBM
    /// </summary>
    /// <remarks>The registry prints this identifier as "0x49 0x42 0x4d 0x00"; the certificate value uses uppercase hexadecimal digits (TCG EK Credential Profile 2.7 §3.1.2).</remarks>
    public const string IBM = "id:49424D00";

    /// <summary>
    ///     Infineon
    /// </summary>
    public const string Infineon = "id:49465800";

    /// <summary>
    ///     Intel
    /// </summary>
    public const string Intel = "id:494E5443";

    /// <summary>
    ///     Lenovo
    /// </summary>
    public const string Lenovo = "id:4C454E00";

    /// <summary>
    ///     Microsoft
    /// </summary>
    public const string Microsoft = "id:4D534654";

    /// <summary>
    ///     National Semiconductor (acquired by Texas Instruments)
    /// </summary>
    public const string NationalSemiconductor = "id:4E534D20";

    /// <summary>
    ///     Nations Technologies Inc
    /// </summary>
    public const string Nationz = "id:4E545A00";

    /// <summary>
    ///     NSING
    /// </summary>
    public const string NSING = "id:4E534700";

    /// <summary>
    ///     Nuvoton Technology
    /// </summary>
    public const string NuvotonTechnology = "id:4E544300";

    /// <summary>
    ///     Qualcomm
    /// </summary>
    public const string Qualcomm = "id:51434F4D";

    /// <summary>
    ///     Samsung
    /// </summary>
    public const string Samsung = "id:534D534E";

    /// <summary>
    ///     SecEdge
    /// </summary>
    public const string SecEdge = "id:53454345";

    /// <summary>
    ///     Sinosun
    /// </summary>
    public const string Sinosun = "id:534E5300";

    /// <summary>
    ///     SMSC
    /// </summary>
    public const string SMSC = "id:534D5343";

    /// <summary>
    ///     STMicroelectronics International NV
    /// </summary>
    public const string STMicroelectronics = "id:53544D20";

    /// <summary>
    ///     Texas Instruments
    /// </summary>
    public const string TexasInstruments = "id:54584E00";

    /// <summary>
    ///     Winbond
    /// </summary>
    public const string Winbond = "id:57454300";

    /// <summary>
    ///     Wisekey
    /// </summary>
    public const string Wisekey = "id:5345414C";
}
