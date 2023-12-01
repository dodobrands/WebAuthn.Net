using System;
using System.ComponentModel;
using System.Linq;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;

/// <summary>
///     Decoded <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-packed-attestation">Packed attestation statement</a>.
/// </summary>
public class PackedAttestationStatement : AbstractAttestationStatement
{
    /// <summary>
    ///     Constructs <see cref="PackedAttestationStatement" />.
    /// </summary>
    /// <param name="alg">
    ///     A <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#typedefdef-cosealgorithmidentifier">COSEAlgorithmIdentifier</a> containing the identifier of the algorithm used to generate the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-signature">attestation signature</a>
    /// </param>
    /// <param name="sig">
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-signature">Attestation signature</a>
    /// </param>
    /// <param name="x5C">The elements of this array contain attestnCert (the attestation certificate, encoded in X.509 format) and its certificate chain (if any), each encoded in X.509 format. The attestation certificate attestnCert MUST be the first element in the array.</param>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="alg" /> contains a value that is not defined in <see cref="CoseAlgorithm" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="sig" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException">One of the <paramref name="x5C" /> elements is <see langword="null" /></exception>
    public PackedAttestationStatement(CoseAlgorithm alg, byte[] sig, byte[][]? x5C)
    {
        // alg
        if (!Enum.IsDefined(typeof(CoseAlgorithm), alg))
        {
            throw new InvalidEnumArgumentException(nameof(alg), (int) alg, typeof(CoseAlgorithm));
        }

        Alg = alg;

        // sig
        ArgumentNullException.ThrowIfNull(sig);
        Sig = sig;

        // x5C
        if (x5C is not null)
        {
            // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
            if (x5C.Any(static x => x is null))
            {
                throw new ArgumentException($"One or more objects contained in the '{nameof(x5C)}' array are equal to null.", nameof(x5C));
            }

            X5C = x5C;
        }
    }

    /// <summary>
    ///     A <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#typedefdef-cosealgorithmidentifier">COSEAlgorithmIdentifier</a> containing the identifier of the algorithm used to generate the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-signature">attestation signature</a>
    /// </summary>
    public CoseAlgorithm Alg { get; }

    /// <summary>
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-signature">Attestation signature</a>
    /// </summary>
    public byte[] Sig { get; }

    /// <summary>
    ///     The elements of this array contain attestnCert (the attestation certificate, encoded in X.509 format) and its certificate chain (if any), each encoded in X.509 format. The attestation certificate attestnCert MUST be the first element in the array.
    /// </summary>
    public byte[][]? X5C { get; }
}
