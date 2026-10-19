using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Abstractions;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>12.2.3.4 TPMS_RSA_PARMS (Table 228)</para>
///     <para>A TPM compatible with this specification and supporting RSA shall support two primes and an exponent of zero.</para>
///     <para>An exponent of zero indicates that the exponent is the default of 2^16 + 1. Support for other values is optional. Use of other exponents in duplicated keys is not recommended because the resulting keys would not be interoperable with other TPMs.</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf">TPM 2.0 Library - Part 2: Structures, Version 185, March 12, 2026</a>
///     </para>
/// </remarks>
public class RsaParms : AbstractPublicParms
{
    /// <summary>
    ///     Constructs <see cref="RsaParms" />.
    /// </summary>
    /// <param name="keyBits">Number of bits in the public modulus.</param>
    /// <param name="exponent">The public exponent. An odd number greater than 2. The decoder replaces the wire value 0 (the default exponent) with 2^16 + 1.</param>
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
    ///     The public exponent. An odd number greater than 2. The decoder replaces the wire value 0 (the default exponent) with 2^16 + 1.
    /// </summary>
    public uint Exponent { get; }
}
