using System;
using System.ComponentModel;
using System.Linq;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;

/// <summary>
///     Decoded <a href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">TPM attestation statement</a>.
/// </summary>
public class TpmAttestationStatement : AbstractAttestationStatement
{
    /// <summary>
    ///     Constructs <see cref="TpmAttestationStatement" />.
    /// </summary>
    /// <param name="ver">The version of the TPM specification to which the signature conforms. MUST be "2.0" (the tpmStmtFormat syntax fixes it to that literal; the decoder rejects every other value).</param>
    /// <param name="alg">
    ///     A <a href="https://www.w3.org/TR/webauthn-3/#typedefdef-cosealgorithmidentifier">COSEAlgorithmIdentifier</a> containing the identifier of the algorithm used to generate the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#attestation-signature">attestation signature</a>.
    /// </param>
    /// <param name="x5C">aikCert followed by its certificate chain, in X.509 encoding.</param>
    /// <param name="sig">
    ///     <para>
    ///         The <a href="https://www.w3.org/TR/webauthn-3/#attestation-signature">attestation signature</a>, in the form of a TPMT_SIGNATURE structure as specified in <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">[TPMv2-Part2]</a> section
    ///         11.3.4.
    ///     </para>
    ///     <para>
    ///         Note: WebAuthn describes 'sig' as a TPMT_SIGNATURE (TPM 2.0 Library Part 2 v185 §11.3.6), but authenticators (Windows Hello), the FIDO conformance tools and interoperable relying-party libraries put the bare signature value here,
    ///         encoded per <a href="https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types">WebAuthn §6.5.6</a> (PKCS#1 v1.5 or PSS for RSA, a DER-encoded ECDSA-Sig-Value for ECDSA); this library verifies it as such.
    ///     </para>
    /// </param>
    /// <param name="certInfo">
    ///     The TPMS_ATTEST structure over which the above signature was computed, as specified in <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">[TPMv2-Part2]</a>
    ///     (TPM 2.0 Library Part 2 v185 §10.11.12; §10.12.8 in the rev 01.38 edition cited by WebAuthn L3). The TPM2B_ATTEST size prefix is not included.
    /// </param>
    /// <param name="pubArea">
    ///     The TPMT_PUBLIC structure (see <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">[TPMv2-Part2]</a>, TPM 2.0 Library Part 2 v185 §12.2.4, Table 235) used by the TPM to represent the credential public key.
    ///     The two-byte size prefix of the TPM2B_PUBLIC returned by TPM2_ReadPublic is not included.
    /// </param>
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
        if (!Enum.IsDefined(alg))
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
    ///     The version of the TPM specification to which the signature conforms. MUST be "2.0" (the tpmStmtFormat syntax fixes it to that literal; the decoder rejects every other value).
    /// </summary>
    public string Ver { get; }

    /// <summary>
    ///     A <a href="https://www.w3.org/TR/webauthn-3/#typedefdef-cosealgorithmidentifier">COSEAlgorithmIdentifier</a> containing the identifier of the algorithm used to generate the <a href="https://www.w3.org/TR/webauthn-3/#attestation-signature">attestation signature</a>.
    /// </summary>
    public CoseAlgorithm Alg { get; }

    /// <summary>
    ///     aikCert followed by its certificate chain, in X.509 encoding.
    /// </summary>
    public byte[][] X5C { get; }

    /// <summary>
    ///     <para>
    ///         The <a href="https://www.w3.org/TR/webauthn-3/#attestation-signature">attestation signature</a>, in the form of a TPMT_SIGNATURE structure as specified in <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">[TPMv2-Part2]</a> section
    ///         11.3.4.
    ///     </para>
    ///     <para>
    ///         Note: WebAuthn describes 'sig' as a TPMT_SIGNATURE (TPM 2.0 Library Part 2 v185 §11.3.6), but authenticators (Windows Hello), the FIDO conformance tools and interoperable relying-party libraries put the bare signature value here,
    ///         encoded per <a href="https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types">WebAuthn §6.5.6</a> (PKCS#1 v1.5 or PSS for RSA, a DER-encoded ECDSA-Sig-Value for ECDSA); this library verifies it as such.
    ///     </para>
    /// </summary>
    public byte[] Sig { get; }

    /// <summary>
    ///     The TPMS_ATTEST structure over which the above signature was computed, as specified in <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">[TPMv2-Part2]</a>
    ///     (TPM 2.0 Library Part 2 v185 §10.11.12; §10.12.8 in the rev 01.38 edition cited by WebAuthn L3). The TPM2B_ATTEST size prefix is not included.
    /// </summary>
    public byte[] CertInfo { get; }

    /// <summary>
    ///     The TPMT_PUBLIC structure (see <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">[TPMv2-Part2]</a>, TPM 2.0 Library Part 2 v185 §12.2.4, Table 235) used by the TPM to represent the credential public key.
    ///     The two-byte size prefix of the TPM2B_PUBLIC returned by TPM2_ReadPublic is not included.
    /// </summary>
    public byte[] PubArea { get; }
}
