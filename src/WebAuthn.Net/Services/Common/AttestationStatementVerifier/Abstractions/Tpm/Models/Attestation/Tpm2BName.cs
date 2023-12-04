namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     TPM2B_NAME
///     <para>
///         The type-specific attestation information.
///     </para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
///     </para>
///     <para>10.5.3 TPM2B_NAME</para>
/// </remarks>
public class Tpm2BName
{
    public Tpm2BName(TpmtHa? digest, TpmHandle? handle)
    {
        Digest = digest;
        Handle = handle;
    }

    public TpmtHa? Digest { get; }

    public TpmHandle? Handle { get; }
}
