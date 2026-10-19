namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>7.1 Introduction (Handles)</para>
///     <para>Handles are 32-bit values used to reference shielded locations of various types within the TPM.</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf">TPM 2.0 Library - Part 2: Structures, Version 185, March 12, 2026</a>
///     </para>
/// </remarks>
public class TpmHandle
{
    // 7 Handles
    // 7.1 Introduction
    // Handles are 32-bit values used to reference shielded locations of various types within the TPM.
    // Table 32: Definition of Types for TPM_HANDLE
    // | Type   | Name       | Description
    // | UINT32 | TPM_HANDLE |

    /// <summary>
    ///     Constructs <see cref="TpmHandle" />.
    /// </summary>
    /// <param name="handle">The value of TPM_HANDLE.</param>
    public TpmHandle(uint handle)
    {
        Handle = handle;
    }

    /// <summary>
    ///     The value of TPM_HANDLE.
    /// </summary>
    public uint Handle { get; }
}
