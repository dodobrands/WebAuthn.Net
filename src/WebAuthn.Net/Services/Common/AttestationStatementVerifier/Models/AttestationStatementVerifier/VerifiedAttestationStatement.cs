using System;
using System.ComponentModel;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;

/// <summary>
///     Artifact of a successfully verified attestation statement.
/// </summary>
public class VerifiedAttestationStatement
{
    /// <summary>
    ///     Constructs <see cref="VerifiedAttestationStatement" />.
    /// </summary>
    /// <param name="fmt">
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement-format-identifier">Attestation statement format identifier</a>.
    /// </param>
    /// <param name="attestationType"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation-types">Attestation type</a>, inferred during the verification process of the attestation statement.</param>
    /// <param name="attestationTrustPath">The attestation trust path - a chain of X509v3 certificates, each serialized to a byte array. Can be <see langword="null" />. If not <see langword="null" />, it's guaranteed to contain one element or more.</param>
    /// <param name="attestationRootCertificates">Root CA X509v3 certificates for validating the chain specified in the attestation trust path. Contains either <see langword="null" /> or a collection with at least one element.</param>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="fmt" /> contains a value that is not defined in <see cref="AttestationStatementFormat" /></exception>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="attestationType" /> contains a value that is not defined in <see cref="AttestationType" /></exception>
    /// <exception cref="ArgumentException"><paramref name="attestationRootCertificates" /> is empty. It must be either <see langword="null" /> or contain at least one value.</exception>
    public VerifiedAttestationStatement(
        AttestationStatementFormat fmt,
        AttestationType attestationType,
        byte[][]? attestationTrustPath,
        UniqueByteArraysCollection? attestationRootCertificates)
    {
        // fmt
        if (!Enum.IsDefined(typeof(AttestationStatementFormat), fmt))
        {
            throw new InvalidEnumArgumentException(nameof(fmt), (int) fmt, typeof(AttestationStatementFormat));
        }

        Fmt = fmt;

        // attestationType
        if (!Enum.IsDefined(typeof(AttestationType), attestationType))
        {
            throw new InvalidEnumArgumentException(nameof(attestationType), (int) attestationType, typeof(AttestationType));
        }

        AttestationType = attestationType;

        // attestationTrustPath
        if (attestationTrustPath?.Length > 0)
        {
            AttestationTrustPath = attestationTrustPath;
        }

        // attestationRootCertificates
        if (attestationRootCertificates is not null)
        {
            if (attestationRootCertificates.Count == 0)
            {
                throw new ArgumentException($"The {nameof(attestationRootCertificates)} must contain at least one element", nameof(attestationRootCertificates));
            }

            AttestationRootCertificates = attestationRootCertificates;
        }
    }

    /// <summary>
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement-format-identifier">Attestation statement format identifier</a>.
    /// </summary>
    public AttestationStatementFormat Fmt { get; }

    /// <summary>
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attestation-types">Attestation type</a>, inferred during the verification process of the attestation statement.
    /// </summary>
    public AttestationType AttestationType { get; }

    /// <summary>
    ///     The attestation trust path - a chain of X509v3 certificates, each serialized to a byte array. Can be <see langword="null" />. If not <see langword="null" />, it's guaranteed to contain one element or more.
    /// </summary>
    public byte[][]? AttestationTrustPath { get; }

    /// <summary>
    ///     Root CA X509v3 certificates for validating the chain specified in the attestation trust path. Contains either <see langword="null" /> or a collection with at least one element.
    /// </summary>
    public UniqueByteArraysCollection? AttestationRootCertificates { get; }
}
