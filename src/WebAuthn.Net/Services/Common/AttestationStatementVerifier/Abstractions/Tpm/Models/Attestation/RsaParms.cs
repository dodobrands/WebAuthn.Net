using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Abstractions;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>12.2.3.5 TPMS_RSA_PARMS</para>
///     <para>A TPM compatible with this specification and supporting RSA shall support two primes and an exponent of zero.</para>
///     <para> An exponent of zero indicates that the exponent is the default of 2^16 + 1. Support for other values is optional. Use of other exponents in duplicated keys is not recommended because the resulting keys would not be interoperable with other TPMs.</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
///     </para>
/// </remarks>
public class RsaParms : AbstractPublicParms
{
    /// <summary>
    ///     Constructs <see cref="RsaParms" />.
    /// </summary>
    /// <param name="keyBits">Number of bits in the public modulus.</param>
    /// <param name="exponent">The public exponent. A prime number greater than 2.</param>
    public RsaParms(ushort keyBits, uint exponent)
    {
        KeyBits = keyBits;
        Exponent = exponent;
    }

    /// <summary>
    ///     Number of bits in the public modulus.
    /// </summary>
    public ushort KeyBits { get; }

    /// <summary>
    ///     The public exponent. A prime number greater than 2.
    /// </summary>
    public uint Exponent { get; }
}
