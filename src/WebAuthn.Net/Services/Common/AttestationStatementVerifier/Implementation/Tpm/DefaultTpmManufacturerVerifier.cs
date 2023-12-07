using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Constants;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;

/// <summary>
///     Default implementation of <see cref="ITpmManufacturerVerifier" />.
/// </summary>
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultTpmManufacturerVerifier : ITpmManufacturerVerifier
{
    /// <inheritdoc />
    public virtual Result<UniqueByteArraysCollection?> IsValid(string tpmManufacturer)
    {
        return tpmManufacturer switch
        {
            TpmManufacturers.AMD => Result<UniqueByteArraysCollection?>.Success(new(TpmRoots.AMD)),
            TpmManufacturers.Atmel => Result<UniqueByteArraysCollection?>.Success(new(TpmRoots.Atmel)),
            TpmManufacturers.Infineon => Result<UniqueByteArraysCollection?>.Success(new(TpmRoots.Infineon)),
            TpmManufacturers.Intel => Result<UniqueByteArraysCollection?>.Success(new(TpmRoots.Intel)),
            TpmManufacturers.Microsoft => Result<UniqueByteArraysCollection?>.Success(new(TpmRoots.Microsoft)),
            TpmManufacturers.Nationz => Result<UniqueByteArraysCollection?>.Success(new(TpmRoots.Nationz)),
            TpmManufacturers.NuvotonTechnology => Result<UniqueByteArraysCollection?>.Success(new(TpmRoots.NuvotonTechnology)),
            TpmManufacturers.STMicroelectronics => Result<UniqueByteArraysCollection?>.Success(new(TpmRoots.STMicroelectronics)),
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
                or TpmManufacturers.Winbond => Result<UniqueByteArraysCollection?>.Success(new(TpmRoots.Microsoft)),
            _ => Result<UniqueByteArraysCollection?>.Fail()
        };
    }
}
