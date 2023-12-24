using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;

namespace WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;

/// <summary>
///     Attested Credential Data
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-attested-credential-data">Web Authentication: An API for accessing Public Key Credentials Level 3 - §6.5.2. Attested Credential Data</a>
/// </remarks>
public class AttestedCredentialData
{
    /// <summary>
    ///     Constructs <see cref="AttestedCredentialData" />.
    /// </summary>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    /// <param name="credentialId">
    ///     A probabilistically-unique <a href="https://infra.spec.whatwg.org/#byte-sequence">byte sequence</a> identifying a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a> and its
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-assertion">authentication assertions</a>. At least 16 bytes long. At most 1023 bytes long.
    /// </param>
    /// <param name="credentialPublicKey">The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-public-key">credential public key</a>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="aaguid" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="credentialId" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException">The length of <paramref name="aaguid" /> is not equal to 16</exception>
    /// <exception cref="ArgumentException">The length of <paramref name="credentialId" /> is less than 16</exception>
    /// <exception cref="ArgumentException">The length of <paramref name="credentialId" /> is greater than 1023</exception>
    public AttestedCredentialData(
        [SuppressMessage("ReSharper", "IdentifierTypo")]
        Guid aaguid,
        byte[] credentialId,
        AbstractCoseKey credentialPublicKey)
    {
        ArgumentNullException.ThrowIfNull(credentialId);

        if (credentialId.Length < 16)
        {
            // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id
            // At least 16 bytes that include at least 100 bits of entropy
            throw new ArgumentException($"The minimum length of the {nameof(credentialId)} is 16.", nameof(credentialId));
        }

        if (credentialId.Length > 1023)
        {
            // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id
            // At least 16 bytes that include at least 100 bits of entropy
            throw new ArgumentException($"The max length of the {nameof(credentialId)} is 1023.", nameof(credentialId));
        }

        Aaguid = aaguid;
        CredentialId = credentialId;
        CredentialPublicKey = credentialPublicKey;
    }

    /// <summary>
    ///     The AAGUID of the authenticator.
    /// </summary>
    public Guid Aaguid { get; }

    /// <summary>
    ///     A probabilistically-unique <a href="https://infra.spec.whatwg.org/#byte-sequence">byte sequence</a> identifying a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential source</a> and its
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-assertion">authentication assertions</a>. At least 16 bytes long. At most 1023 bytes long.
    /// </summary>
    public byte[] CredentialId { get; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-public-key">credential public key</a>.
    /// </summary>
    public AbstractCoseKey CredentialPublicKey { get; }
}
