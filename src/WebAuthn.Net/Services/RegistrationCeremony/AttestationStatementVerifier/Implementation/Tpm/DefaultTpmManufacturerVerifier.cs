using System.Collections.Generic;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.Tpm;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.Tpm;

public class DefaultTpmManufacturerVerifier : ITpmManufacturerVerifier
{
    // https://trustedcomputinggroup.org/resource/vendor-id-registry/
    // https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Version-1.06-Revision-0.94_pub.pdf
    private static readonly IReadOnlySet<string> ValidManufacturers = new HashSet<string>
    {
        "id:414D4400", // AMD
        "id:414E5400", // Ant Group
        "id:41544D4C", // Atmel
        "id:4252434D", // Broadcom
        "id:4353434F", // Cisco
        "id:464C5953", // Flyslice Technologies
        "id:524F4343", // Fuzhou Rockchip
        "id:474F4F47", // Google
        "id:48504900", // HPI
        "id:48504500", // HPE
        "id:48495349", // Huawei
        "id:49424d00", // IBM
        "id:49465800", // Infineon
        "id:494E5443", // Intel
        "id:4C454E00", // Lenovo
        "id:4D534654", // Microsoft
        "id:4E534D20", // National Semiconductor
        "id:4E545A00", // Nationz
        "id:4E544300", // Nuvoton Technology
        "id:51434F4D", // Qualcomm
        "id:534D534E", // Samsung
        "id:534E5300", // Sinosun
        "id:534D5343", // SMSC
        "id:53544D20", // ST Microelectronics
        "id:54584E00", // Texas Instruments
        "id:57454300" // Winbond
    };

    public bool IsValid(string tpmManufacturer)
    {
        return ValidManufacturers.Contains(tpmManufacturer);
    }
}
