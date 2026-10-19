namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums.Extensions;

/// <summary>
///     Extension methods for <see cref="TpmAlgIdHash" />.
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf">TPM 2.0 Library - Part 2: Structures, Version 185, March 12, 2026</a>
///     </para>
/// </remarks>
public static class TpmAlgIdHashExtensions
{
    /// <summary>
    ///     Returns the size in octets of the digest produced by the specified hash algorithm, as fixed by the TPMU_HA union (TPM 2.0 Library Part 2, Version 185, 10.2.1, Table 88).
    /// </summary>
    /// <param name="hashAlg">The hash algorithm (the hashAlg selector of a TPMT_HA, the nameAlg of a TPMT_PUBLIC or the hashAlg of a TPMS_SCHEME_HASH).</param>
    /// <param name="digestSize">The size of the digest in octets if <paramref name="hashAlg" /> is a known hash algorithm; otherwise 0.</param>
    /// <returns><see langword="true" /> if <paramref name="hashAlg" /> is a known hash algorithm and its digest size has been returned in <paramref name="digestSize" />; otherwise <see langword="false" />.</returns>
    public static bool TryGetDigestSize(this TpmAlgIdHash hashAlg, out int digestSize)
    {
        // 10.2.1 TPMU_HA
        // Table 88: Definition of TPMU_HA Union
        // | Parameter        | Type | Selector
        // | sha1[20]         | BYTE | TPM_ALG_SHA1
        // | sha256[32]       | BYTE | TPM_ALG_SHA256
        // | sha384[48]       | BYTE | TPM_ALG_SHA384
        // | sha512[64]       | BYTE | TPM_ALG_SHA512
        // | sha256_192[24]   | BYTE | TPM_ALG_SHA256_192
        // | sm3_256[32]      | BYTE | TPM_ALG_SM3_256
        // | sha3_256[32]     | BYTE | TPM_ALG_SHA3_256
        // | sha3_384[48]     | BYTE | TPM_ALG_SHA3_384
        // | sha3_512[64]     | BYTE | TPM_ALG_SHA3_512
        // | shake256_192[24] | BYTE | TPM_ALG_SHAKE256_192
        // | shake256_256[32] | BYTE | TPM_ALG_SHAKE256_256
        // | shake256_512[64] | BYTE | TPM_ALG_SHAKE256_512
        // | null             |      | TPM_ALG_NULL
        // Every member of TpmAlgIdHash (the TPMI_ALG_HASH list of Table 77) is listed here; any other selector is rejected, including TPM_ALG_NULL:
        // for a nameAlg of TPM_ALG_NULL the reference implementation produces an empty Name (PublicMarshalAndComputeName), never a TPMT_HA.
        // Knowing the size of a digest is not the same as being able to compute it: the code that hashes decides which algorithms it supports and fails closed for the rest.
        switch (hashAlg)
        {
            case TpmAlgIdHash.Sha1:
                {
                    digestSize = 20;
                    return true;
                }
            case TpmAlgIdHash.Sha256_192:
            case TpmAlgIdHash.Shake256_192:
                {
                    digestSize = 24;
                    return true;
                }
            case TpmAlgIdHash.Sha256:
            case TpmAlgIdHash.Sm3_256:
            case TpmAlgIdHash.Sha3_256:
            case TpmAlgIdHash.Shake256_256:
                {
                    digestSize = 32;
                    return true;
                }
            case TpmAlgIdHash.Sha384:
            case TpmAlgIdHash.Sha3_384:
                {
                    digestSize = 48;
                    return true;
                }
            case TpmAlgIdHash.Sha512:
            case TpmAlgIdHash.Sha3_512:
            case TpmAlgIdHash.Shake256_512:
                {
                    digestSize = 64;
                    return true;
                }
            default:
                {
                    digestSize = 0;
                    return false;
                }
        }
    }
}
