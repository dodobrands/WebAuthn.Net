using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Abstractions;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>11.2.4.6 TPM2B_PUBLIC_KEY_RSA (Table 194)</para>
///     <para>This sized buffer holds the largest RSA public key supported by the TPM.</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf">TPM 2.0 Library - Part 2: Structures, Version 185, March 12, 2026</a>
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
