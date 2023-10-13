using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Abstractions.Tpm;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Manufacturer;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Manufacturer.Constants;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultTpmManufacturerVerifier : ITpmManufacturerVerifier
{
    protected static readonly HashSet<string> ValidManufacturers = new(StringComparer.Ordinal)
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
                or TpmManufacturers.Winbond => new(true, null),
            _ => new(false, null)
        };
    }
}
