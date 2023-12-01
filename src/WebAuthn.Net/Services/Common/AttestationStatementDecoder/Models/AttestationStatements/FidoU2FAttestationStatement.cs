using System;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;

/// <summary>
///     Decoded <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-fido-u2f-attestation">FIDO U2F attestation statement</a>.
/// </summary>
public class FidoU2FAttestationStatement : AbstractAttestationStatement
{
    /// <summary>
    ///     Constructs <see cref="FidoU2FAttestationStatement" />.
    /// </summary>
    /// <param name="sig">
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-signature">attestation signature</a>. The signature was calculated over the (raw) U2F registration response message [FIDO-U2F-Message-Formats] received by the client from the
    ///     authenticator.
    /// </param>
    /// <param name="x5C">A single element array containing the attestation certificate in X.509 format.</param>
    /// <exception cref="ArgumentNullException"><paramref name="sig" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="x5C" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException"><paramref name="x5C" /> does not contain exactly 1 element</exception>
    /// <exception cref="ArgumentException">The only element in <paramref name="x5C" /> is <see langword="null" /></exception>
    public FidoU2FAttestationStatement(byte[] sig, byte[][] x5C)
    {
        // sig
        ArgumentNullException.ThrowIfNull(sig);
        Sig = sig;

        // x5C
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        ArgumentNullException.ThrowIfNull(x5C);
        if (x5C.Length != 1)
        {
            throw new ArgumentException($"{nameof(x5C)} should be a single element array.", nameof(x5C));
        }

        if (x5C[0] is null)
        {
            throw new ArgumentException($"One or more objects contained in the {nameof(x5C)} array are equal to null.", nameof(x5C));
        }

        X5C = x5C;
    }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-signature">attestation signature</a>. The signature was calculated over the (raw) U2F registration response message [FIDO-U2F-Message-Formats] received by the client from the authenticator.
    /// </summary>
    public byte[] Sig { get; }

    /// <summary>
    ///     A single element array containing the attestation certificate in X.509 format.
    /// </summary>
    public byte[][] X5C { get; }
}
