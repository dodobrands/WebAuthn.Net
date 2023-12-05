namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>7.1 TPM_HANDLE</para>
///     <para>Handles are 32-bit values used to reference shielded locations of various types within the TPM.</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
///     </para>
/// </remarks>
public class TpmHandle
{
    // 7 Handles
    // 7.1 Introduction
    // Handles are 32-bit values used to reference shielded locations of various types within the TPM.
    // Table 26 — Definition of Types for Handles
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
