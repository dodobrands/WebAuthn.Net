using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Constants;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultTpmManufacturerVerifier : ITpmManufacturerVerifier
{
    public virtual Result<byte[][]> IsValid(string tpmManufacturer)
    {
        return tpmManufacturer switch
        {
            TpmManufacturers.AMD => Result<byte[][]>.Success(TpmRoots.AMD),
            TpmManufacturers.Atmel => Result<byte[][]>.Success(TpmRoots.Atmel),
            TpmManufacturers.Infineon => Result<byte[][]>.Success(TpmRoots.Infineon),
            TpmManufacturers.Intel => Result<byte[][]>.Success(TpmRoots.Intel),
            TpmManufacturers.Microsoft => Result<byte[][]>.Success(TpmRoots.Microsoft),
            TpmManufacturers.Nationz => Result<byte[][]>.Success(TpmRoots.Nationz),
            TpmManufacturers.NuvotonTechnology => Result<byte[][]>.Success(TpmRoots.NuvotonTechnology),
            TpmManufacturers.STMicroelectronics => Result<byte[][]>.Success(TpmRoots.STMicroelectronics),
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
                or TpmManufacturers.Winbond => Result<byte[][]>.Success(TpmRoots.Microsoft),
            _ => Result<byte[][]>.Fail()
        };
    }
}
