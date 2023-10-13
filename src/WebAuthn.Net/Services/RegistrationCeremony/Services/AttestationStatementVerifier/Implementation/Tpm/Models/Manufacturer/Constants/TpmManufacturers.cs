using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Manufacturer.Constants;

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
    public const string AMD = "id:414D4400";
    public const string AntGroup = "id:414E5400";
    public const string Atmel = "id:41544D4C";
    public const string Broadcom = "id:4252434D";
    public const string Cisco = "id:4353434F";
    public const string FlysliceTechnologies = "id:464C5953";
    public const string FuzhouRockchip = "id:524F4343";
    public const string Google = "id:474F4F47";
    public const string HPI = "id:48504900";
    public const string HPE = "id:48504500";
    public const string Huawei = "id:48495349";
    public const string IBM = "id:49424d00";
    public const string Infineon = "id:49465800";
    public const string Intel = "id:494E5443";
    public const string Lenovo = "id:4C454E00";
    public const string Microsoft = "id:4D534654";
    public const string NationalSemiconductor = "id:4E534D20";
    public const string Nationz = "id:4E545A00";
    public const string NuvotonTechnology = "id:4E544300";
    public const string Qualcomm = "id:51434F4D";
    public const string Samsung = "id:534D534E";
    public const string Sinosun = "id:534E5300";
    public const string SMSC = "id:534D5343";
    public const string STMicroelectronics = "id:53544D20";
    public const string TexasInstruments = "id:54584E00";
    public const string Winbond = "id:57454300";
}
