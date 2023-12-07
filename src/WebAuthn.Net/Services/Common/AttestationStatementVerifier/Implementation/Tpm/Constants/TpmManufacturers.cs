using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Constants;

/// <summary>
///     Tpm Manufacturers mapped to their IDs
/// </summary>
/// <remarks>
///     <para>https://trustedcomputinggroup.org/resource/vendor-id-registry</para>
///     <para>https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Version-1.06-Revision-0.94_pub.pdf</para>
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
    public const string IBM = "id:49424d00";

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
}
