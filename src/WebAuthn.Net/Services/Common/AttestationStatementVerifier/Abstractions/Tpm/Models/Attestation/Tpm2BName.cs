namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>10.4.3 TPM2B_NAME</para>
///     <para>This buffer holds a Name for any entity type. If size is four, the Name is a handle; if size is zero, no Name is present; otherwise the Name is a TPM_ALG_ID followed by the digest produced by that algorithm.</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf">TPM 2.0 Library - Part 2: Structures, Version 185, March 12, 2026</a>
///     </para>
/// </remarks>
public class Tpm2BName
{
    /// <summary>
    ///     Constructs <see cref="Tpm2BName" />.
    /// </summary>
    /// <param name="digest">When the Name is a digest (TPMU_NAME.digest, Table 104); <see langword="null" /> when the Name is a handle or no Name is present.</param>
    /// <param name="handle">When the Name is a handle (TPMU_NAME.handle, Table 104); <see langword="null" /> otherwise.</param>
    public Tpm2BName(TpmtHa? digest, TpmHandle? handle)
    {
        Digest = digest;
        Handle = handle;
    }

    /// <summary>
    ///     When the Name is a digest (TPMU_NAME.digest, Table 104); <see langword="null" /> when the Name is a handle or no Name is present.
    /// </summary>
    public TpmtHa? Digest { get; }

    /// <summary>
    ///     When the Name is a handle (TPMU_NAME.handle, Table 104); <see langword="null" /> otherwise.
    /// </summary>
    public TpmHandle? Handle { get; }
}
