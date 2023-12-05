using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>12.2.4 TPMT_PUBLIC</para>
///     <para>The structure used by the TPM to represent the credential public key.</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
///     </para>
/// </remarks>
public class PubArea
{
    /// <summary>
    ///     Constructs <see cref="PubArea" />.
    /// </summary>
    /// <param name="type">"algorithm" associated with this object.</param>
    /// <param name="nameAlg">algorithm used for computing the Name of the object.</param>
    /// <param name="objectAttributes">Attributes that, along with type, determine the manipulations of this object.</param>
    /// <param name="parameters">The algorithm or structure details.</param>
    /// <param name="unique">
    ///     <para>The unique identifier of the structure.</para>
    ///     <para>For an asymmetric key, this would be the public key.</para>
    /// </param>
    public PubArea(
        TpmAlgPublic type,
        TpmAlgIdHash nameAlg,
        ObjectAttributes objectAttributes,
        AbstractPublicParms parameters,
        AbstractUnique unique)
    {
        Type = type;
        NameAlg = nameAlg;
        ObjectAttributes = objectAttributes;
        Parameters = parameters;
        Unique = unique;
    }

    /// <summary>
    ///     "algorithm" associated with this object.
    /// </summary>
    public TpmAlgPublic Type { get; }

    /// <summary>
    ///     algorithm used for computing the Name of the object.
    /// </summary>
    public TpmAlgIdHash NameAlg { get; }

    /// <summary>
    ///     Attributes that, along with type, determine the manipulations of this object.
    /// </summary>
    public ObjectAttributes ObjectAttributes { get; }

    /// <summary>
    ///     The algorithm or structure details.
    /// </summary>
    public AbstractPublicParms Parameters { get; }

    /// <summary>
    ///     <para>The unique identifier of the structure.</para>
    ///     <para>For an asymmetric key, this would be the public key.</para>
    /// </summary>
    public AbstractUnique Unique { get; }
}
