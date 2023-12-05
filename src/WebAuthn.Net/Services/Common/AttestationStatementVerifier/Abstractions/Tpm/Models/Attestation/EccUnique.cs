using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Abstractions;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>11.2.5.2 TPMS_ECC_POINT</para>
///     <para>This structure holds two ECC coordinates that, together, make up an ECC point</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
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
