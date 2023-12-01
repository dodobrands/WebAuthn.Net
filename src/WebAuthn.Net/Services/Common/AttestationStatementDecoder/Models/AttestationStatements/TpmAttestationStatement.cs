using System;
using System.ComponentModel;
using System.Linq;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;

/// <summary>
///     Decoded <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-tpm-attestation">TPM attestation statement</a>.
/// </summary>
public class TpmAttestationStatement : AbstractAttestationStatement
{
    /// <summary>
    ///     Constructs <see cref="TpmAttestationStatement" />.
    /// </summary>
    /// <param name="ver">The version of the TPM specification to which the signature conforms.</param>
    /// <param name="alg">
    ///     A <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#typedefdef-cosealgorithmidentifier">COSEAlgorithmIdentifier</a> containing the identifier of the algorithm used to generate the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-signature">attestation signature</a>
    /// </param>
    /// <param name="x5C">aikCert followed by its certificate chain, in X.509 encoding.</param>
    /// <param name="sig">The attestation signature, in the form of a TPMT_SIGNATURE structure as specified in <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">[TPMv2-Part2]</a> section 11.3.4.</param>
    /// <param name="certInfo">The TPMS_ATTEST structure over which the above signature was computed, as specified in <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">[TPMv2-Part2]</a> section 10.12.12.</param>
    /// <param name="pubArea">The TPMT_PUBLIC structure (see <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">[TPMv2-Part2]</a> section 12.2.4) used by the TPM to represent the credential public key.</param>
    /// <exception cref="ArgumentNullException"><paramref name="ver" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException"><paramref name="ver" /> is empty</exception>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="alg" /> contains a value that is not defined in <see cref="CoseAlgorithm" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="x5C" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException">One of the <paramref name="x5C" /> elements is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="sig" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="certInfo" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="pubArea" /> is <see langword="null" /></exception>
    public TpmAttestationStatement(string ver, CoseAlgorithm alg, byte[][] x5C, byte[] sig, byte[] certInfo, byte[] pubArea)
    {
        // ver
        ArgumentNullException.ThrowIfNull(ver);
        if (string.IsNullOrEmpty(ver))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(ver));
        }

        Ver = ver;

        // alg
        if (!Enum.IsDefined(typeof(CoseAlgorithm), alg))
        {
            throw new InvalidEnumArgumentException(nameof(alg), (int) alg, typeof(CoseAlgorithm));
        }

        Alg = alg;

        // x5C
        ArgumentNullException.ThrowIfNull(x5C);
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (x5C.Any(static x => x is null))
        {
            throw new ArgumentException($"One or more objects contained in the '{nameof(x5C)}' array are equal to null.", nameof(x5C));
        }

        X5C = x5C;

        // sig
        ArgumentNullException.ThrowIfNull(sig);
        Sig = sig;

        // certInfo
        ArgumentNullException.ThrowIfNull(certInfo);
        CertInfo = certInfo;

        // pubArea
        ArgumentNullException.ThrowIfNull(pubArea);
        PubArea = pubArea;
    }

    /// <summary>
    ///     The version of the TPM specification to which the signature conforms.
    /// </summary>
    public string Ver { get; }

    /// <summary>
    ///     A <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#typedefdef-cosealgorithmidentifier">COSEAlgorithmIdentifier</a> containing the identifier of the algorithm used to generate the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-signature">attestation signature</a>
    /// </summary>
    public CoseAlgorithm Alg { get; }

    /// <summary>
    ///     aikCert followed by its certificate chain, in X.509 encoding.
    /// </summary>
    public byte[][] X5C { get; }

    /// <summary>
    ///     The attestation signature, in the form of a TPMT_SIGNATURE structure as specified in <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">[TPMv2-Part2]</a> section 11.3.4.
    /// </summary>
    public byte[] Sig { get; }

    /// <summary>
    ///     The TPMS_ATTEST structure over which the above signature was computed, as specified in <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">[TPMv2-Part2]</a> section 10.12.12.
    /// </summary>
    public byte[] CertInfo { get; }

    /// <summary>
    ///     The TPMT_PUBLIC structure (see <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">[TPMv2-Part2]</a> section 12.2.4) used by the TPM to represent the credential public key.
    /// </summary>
    public byte[] PubArea { get; }
}
