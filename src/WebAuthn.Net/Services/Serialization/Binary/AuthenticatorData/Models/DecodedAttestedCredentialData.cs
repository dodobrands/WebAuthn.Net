using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.Serialization.Cbor.CredentialPublicKey.Models;

namespace WebAuthn.Net.Services.Serialization.Binary.AuthenticatorData.Models;

/// <summary>
///     Decoded representation of <a href="https://www.w3.org/TR/webauthn-3/#attested-credential-data">attested credential data</a>.
/// </summary>
public class DecodedAttestedCredentialData
{
    /// <summary>
    ///     Constructs <see cref="DecodedAttestedCredentialData" />.
    /// </summary>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    /// <param name="credentialId">
    ///     A probabilistically-unique <a href="https://infra.spec.whatwg.org/#byte-sequence">byte sequence</a>
    ///     identifying a <a href="https://www.w3.org/TR/webauthn-3/#public-key-credential-source">public key credential source</a> and its
    ///     <a href="https://www.w3.org/TR/webauthn-3/#authentication-assertion">authentication assertions</a>.
    /// </param>
    /// <param name="credentialPublicKey">The <a href="https://www.w3.org/TR/webauthn-3/#credential-public-key">credential public key</a>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="aaguid" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="credentialId" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException">The length of <paramref name="aaguid" /> is not equal to 16</exception>
    /// <exception cref="ArgumentException">The length of <paramref name="credentialId" /> is less than 16</exception>
    public DecodedAttestedCredentialData(
        [SuppressMessage("ReSharper", "IdentifierTypo")]
        byte[] aaguid,
        byte[] credentialId,
        DecodedCredentialPublicKey? credentialPublicKey)
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
            throw new ArgumentException($"The minimum length of the {nameof(credentialId)} is 16.", nameof(credentialId));
        }


        AAGUID = aaguid;
        CredentialId = credentialId;
        CredentialPublicKey = credentialPublicKey;
    }

    /// <summary>
    ///     The AAGUID of the authenticator.
    /// </summary>
    [SuppressMessage("ReSharper", "IdentifierTypo")]
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public byte[] AAGUID { get; }

    /// <summary>
    ///     A probabilistically-unique <a href="https://infra.spec.whatwg.org/#byte-sequence">byte sequence</a>
    ///     identifying a <a href="https://www.w3.org/TR/webauthn-3/#public-key-credential-source">public key credential source</a> and its
    ///     <a href="https://www.w3.org/TR/webauthn-3/#authentication-assertion">authentication assertions</a>.
    /// </summary>
    public byte[] CredentialId { get; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#credential-public-key">credential public key</a>.
    /// </summary>
    public DecodedCredentialPublicKey? CredentialPublicKey { get; }
}
