namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>10.5.3 TPM2B_NAME</para>
///     <para>The type-specific attestation information.</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
///     </para>
/// </remarks>
public class Tpm2BName
{
    /// <summary>
    ///     Constructs <see cref="Tpm2BName" />.
    /// </summary>
    /// <param name="digest">The Name is a digest (the Name of an entity is used in place of the handle in authorization computations).</param>
    /// <param name="handle">The Name is a handle (the Name of an entity is used in place of the handle in authorization computations).</param>
    public Tpm2BName(TpmtHa? digest, TpmHandle? handle)
    {
        Digest = digest;
        Handle = handle;
    }

    /// <summary>
    ///     The Name is a digest (the Name of an entity is used in place of the handle in authorization computations).
    /// </summary>
    public TpmtHa? Digest { get; }

    /// <summary>
    ///     The Name is a handle (the Name of an entity is used in place of the handle in authorization computations).
    /// </summary>
    public TpmHandle? Handle { get; }
}
