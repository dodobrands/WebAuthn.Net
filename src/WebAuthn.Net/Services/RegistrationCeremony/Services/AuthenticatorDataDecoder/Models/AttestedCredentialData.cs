using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Abstractions;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AuthenticatorDataDecoder.Models;

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
    ///     A probabilistically-unique <a href="https://infra.spec.whatwg.org/#byte-sequence">byte sequence</a> identifying a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source"></a>public key credential source and its
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-assertion"></a>authentication assertions. At least 16 bytes long. At most 1023 bytes long.
    /// </param>
    /// <param name="credentialPublicKey">The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-public-key">credential public key</a>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="aaguid" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="credentialId" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException">The length of <paramref name="aaguid" /> is not equal to 16</exception>
    /// <exception cref="ArgumentException">The length of <paramref name="credentialId" /> is less than 16</exception>
    /// <exception cref="ArgumentException">The length of <paramref name="credentialId" /> is greater than 1023</exception>
    public AttestedCredentialData(
        [SuppressMessage("ReSharper", "IdentifierTypo")]
        byte[] aaguid,
        byte[] credentialId,
        AbstractCoseKey credentialPublicKey)
    {
        if (aaguid == null)
        {
            throw new ArgumentNullException(nameof(aaguid));
        }

        if (credentialId == null)
        {
            throw new ArgumentNullException(nameof(credentialId));
        }

        if (aaguid.Length != 16)
        {
            throw new ArgumentException($"The value must contain exactly 16 bytes, in fact it contains: {aaguid.Length}.", nameof(aaguid));
        }

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
    public byte[] Aaguid { get; }

    /// <summary>
    ///     A probabilistically-unique <a href="https://infra.spec.whatwg.org/#byte-sequence">byte sequence</a> identifying a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source"></a>public key credential source and its
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-assertion"></a>authentication assertions. At least 16 bytes long. At most 1023 bytes long.
    /// </summary>
    public byte[] CredentialId { get; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-public-key">credential public key</a>.
    /// </summary>
    public AbstractCoseKey CredentialPublicKey { get; }
}
