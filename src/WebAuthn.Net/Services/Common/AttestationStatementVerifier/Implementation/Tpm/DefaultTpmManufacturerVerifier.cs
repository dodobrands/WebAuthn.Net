using System;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Constants;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;

/// <summary>
///     Default implementation of <see cref="ITpmManufacturerVerifier" />.
/// </summary>
/// <remarks>
///     <para>
///         The known manufacturers are the vendors of the <a href="https://www.trustedcomputinggroup.org/resources/documents/vendor-id-registry">TCG TPM Vendor ID Registry, Version 1.08 (2026-07-20)</a>, Table 2 (see <see cref="TpmManufacturers" />).
///         The simulator and test identifiers of Table 3 and the identifier used by the FIDO conformance tools (id:FFFFF1D0) are not known to this implementation; an unknown manufacturer is a failure.
///     </para>
///     <para>
///         The identifier is compared case-insensitively: the TCG EK Credential Profile (§3.1.2) mandates uppercase hexadecimal digits, but the registry itself prints some identifiers in lowercase.
///     </para>
///     <para>
///         Vendors with embedded root certificates of their own (see <see cref="TpmRoots" />) get those roots; every other known vendor gets the Microsoft TPM roots, which issue the AIK certificates seen in practice.
///     </para>
/// </remarks>
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultTpmManufacturerVerifier : ITpmManufacturerVerifier
{
    private static readonly FrozenDictionary<string, byte[][]> KnownManufacturers = new Dictionary<string, byte[][]>(StringComparer.OrdinalIgnoreCase)
    {
        // vendors with embedded root certificates of their own (RootCertificates/<Vendor>)
        { TpmManufacturers.AMD, TpmRoots.AMD },
        { TpmManufacturers.Atmel, TpmRoots.Atmel },
        { TpmManufacturers.Infineon, TpmRoots.Infineon },
        { TpmManufacturers.Intel, TpmRoots.Intel },
        { TpmManufacturers.Microsoft, TpmRoots.Microsoft },
        { TpmManufacturers.Nationz, TpmRoots.Nationz },
        { TpmManufacturers.NuvotonTechnology, TpmRoots.NuvotonTechnology },
        { TpmManufacturers.STMicroelectronics, TpmRoots.STMicroelectronics },
        // every other vendor of the registry - the Microsoft TPM roots, which issue the AIK certificates seen in practice
        { TpmManufacturers.AntGroup, TpmRoots.Microsoft },
        { TpmManufacturers.Arm, TpmRoots.Microsoft },
        { TpmManufacturers.Broadcom, TpmRoots.Microsoft },
        { TpmManufacturers.Cisco, TpmRoots.Microsoft },
        { TpmManufacturers.FlysliceTechnologies, TpmRoots.Microsoft },
        { TpmManufacturers.FuzhouRockchip, TpmRoots.Microsoft },
        { TpmManufacturers.Google, TpmRoots.Microsoft },
        { TpmManufacturers.HPI, TpmRoots.Microsoft },
        { TpmManufacturers.HPE, TpmRoots.Microsoft },
        { TpmManufacturers.Huawei, TpmRoots.Microsoft },
        { TpmManufacturers.IBM, TpmRoots.Microsoft },
        { TpmManufacturers.Lenovo, TpmRoots.Microsoft },
        { TpmManufacturers.NationalSemiconductor, TpmRoots.Microsoft },
        { TpmManufacturers.NSING, TpmRoots.Microsoft },
        { TpmManufacturers.Qualcomm, TpmRoots.Microsoft },
        { TpmManufacturers.Samsung, TpmRoots.Microsoft },
        { TpmManufacturers.SecEdge, TpmRoots.Microsoft },
        { TpmManufacturers.Sinosun, TpmRoots.Microsoft },
        { TpmManufacturers.SMSC, TpmRoots.Microsoft },
        { TpmManufacturers.TexasInstruments, TpmRoots.Microsoft },
        { TpmManufacturers.Winbond, TpmRoots.Microsoft },
        { TpmManufacturers.Wisekey, TpmRoots.Microsoft }
    }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    public virtual Result<UniqueByteArraysCollection?> IsValid(string tpmManufacturer)
    {
        if (string.IsNullOrEmpty(tpmManufacturer))
        {
            return Result<UniqueByteArraysCollection?>.Fail();
        }

        return KnownManufacturers.TryGetValue(tpmManufacturer, out var rootCertificates)
            ? Result<UniqueByteArraysCollection?>.Success(new(rootCertificates))
            : Result<UniqueByteArraysCollection?>.Fail();
    }
}
