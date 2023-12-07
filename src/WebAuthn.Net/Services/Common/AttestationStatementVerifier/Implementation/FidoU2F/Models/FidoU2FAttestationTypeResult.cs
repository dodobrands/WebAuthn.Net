using System;
using System.ComponentModel;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.FidoU2F.Models;

/// <summary>
///     The result of getting the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation-types">attestation type</a> for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-fido-u2f-attestation">FIDO U2F attestation statement</a>.
/// </summary>
public class FidoU2FAttestationTypeResult
{
    /// <summary>
    ///     Constructs <see cref="FidoU2FAttestationTypeResult" />.
    /// </summary>
    /// <param name="attestationType">The obtained <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation-types">attestation type</a>.</param>
    /// <param name="attestationRootCertificates">Root CA X509v3 certificates for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-fido-u2f-attestation">FIDO U2F attestation statement</a>.</param>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="attestationType" /> contains a value that is not defined in <see cref="AttestationType" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="attestationRootCertificates" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException"><paramref name="attestationRootCertificates" /> is empty</exception>
    public FidoU2FAttestationTypeResult(
        AttestationType attestationType,
        UniqueByteArraysCollection attestationRootCertificates)
    {
        if (!Enum.IsDefined(typeof(AttestationType), attestationType))
        {
            throw new InvalidEnumArgumentException(nameof(attestationType), (int) attestationType, typeof(AttestationType));
        }

        ArgumentNullException.ThrowIfNull(attestationRootCertificates);
        if (attestationRootCertificates.Count == 0)
        {
            throw new ArgumentException($"The {nameof(attestationRootCertificates)} must contain at least one element", nameof(attestationRootCertificates));
        }

        AttestationType = attestationType;
        AttestationRootCertificates = attestationRootCertificates;
    }

    /// <summary>
    ///     The obtained <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation-types">attestation type</a>.
    /// </summary>
    public AttestationType AttestationType { get; }

    /// <summary>
    ///     Root CA X509v3 certificates for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-fido-u2f-attestation">FIDO U2F attestation statement</a>.
    /// </summary>
    public UniqueByteArraysCollection AttestationRootCertificates { get; }
}
