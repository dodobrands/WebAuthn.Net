using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Abstractions;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>11.2.5.2 TPMS_ECC_POINT (Table 198)</para>
///     <para>This structure holds two ECC coordinates that, together, make up an ECC point.</para>
///     <para>y is zero-length for the Edwards curves (Curve25519 and Curve448), which are not supported by this library; for the supported NIST curves both coordinates are exactly the coordinate size of the curve (32, 48 or 66 bytes).</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf">TPM 2.0 Library - Part 2: Structures, Version 185, March 12, 2026</a>
///     </para>
/// </remarks>
public class EccUnique : AbstractUnique
{
    /// <summary>
    ///     Constructs <see cref="EccUnique" />.
    /// </summary>
    /// <param name="x">X coordinate</param>
    /// <param name="y">Y coordinate</param>
    public EccUnique(byte[] x, byte[] y)
    {
        X = x;
        Y = y;
    }

    /// <summary>
    ///     X coordinate
    /// </summary>
    public byte[] X { get; }

    /// <summary>
    ///     Y coordinate
    /// </summary>
    public byte[] Y { get; }
}
