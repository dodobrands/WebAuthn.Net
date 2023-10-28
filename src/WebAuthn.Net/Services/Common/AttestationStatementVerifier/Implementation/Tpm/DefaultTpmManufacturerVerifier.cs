using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Constants;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Models.Manufacturer;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultTpmManufacturerVerifier : ITpmManufacturerVerifier
{
    public virtual TpmManufacturerVerificationResult IsValid(string tpmManufacturer)
    {
        return tpmManufacturer switch
        {
            TpmManufacturers.AMD => new(true, TpmRoots.AMD),
            TpmManufacturers.Atmel => new(true, TpmRoots.Atmel),
            TpmManufacturers.Infineon => new(true, TpmRoots.Infineon),
            TpmManufacturers.Intel => new(true, TpmRoots.Intel),
            TpmManufacturers.Microsoft => new(true, TpmRoots.Microsoft),
            TpmManufacturers.Nationz => new(true, TpmRoots.Nationz),
            TpmManufacturers.NuvotonTechnology => new(true, TpmRoots.NuvotonTechnology),
            TpmManufacturers.STMicroelectronics => new(true, TpmRoots.STMicroelectronics),
            TpmManufacturers.AntGroup
                or TpmManufacturers.Broadcom
                or TpmManufacturers.Cisco
                or TpmManufacturers.FlysliceTechnologies
                or TpmManufacturers.FuzhouRockchip
                or TpmManufacturers.Google
                or TpmManufacturers.HPI
                or TpmManufacturers.HPE
                or TpmManufacturers.Huawei
                or TpmManufacturers.IBM
                or TpmManufacturers.Lenovo
                or TpmManufacturers.NationalSemiconductor
                or TpmManufacturers.Qualcomm
                or TpmManufacturers.Samsung
                or TpmManufacturers.Sinosun
                or TpmManufacturers.SMSC
                or TpmManufacturers.TexasInstruments
                or TpmManufacturers.Winbond => new(true, TpmRoots.Microsoft),
            _ => new(false, null)
        };
    }
}
