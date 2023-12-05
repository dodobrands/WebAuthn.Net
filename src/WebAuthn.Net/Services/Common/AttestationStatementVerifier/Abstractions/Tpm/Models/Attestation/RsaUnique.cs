using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Abstractions;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
/// </summary>
/// <summary>
///     <para>11.2.4.5 TPM2B_PUBLIC_KEY_RSA</para>
///     <para>This sized buffer holds the largest RSA public key supported by the TPM.</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
///     </para>
/// </remarks>
public class RsaUnique : AbstractUnique
{
    /// <summary>
    ///     Constructs <see cref="RsaUnique" />.
    /// </summary>
    /// <param name="buffer">Value (RSA modulus)</param>
    public RsaUnique(byte[] buffer)
    {
        Buffer = buffer;
    }

    /// <summary>
    ///     Value (RSA modulus).
    /// </summary>
    public byte[] Buffer { get; }
}
