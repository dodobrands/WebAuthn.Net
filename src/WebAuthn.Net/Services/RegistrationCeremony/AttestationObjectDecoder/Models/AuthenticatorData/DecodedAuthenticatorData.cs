using System;
using System.Collections.Generic;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.Enums;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AuthenticatorData;

/// <summary>
///     Decoded representation of <a href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">authenticator data</a>.
/// </summary>
public class DecodedAuthenticatorData
{
    /// <summary>
    ///     Constructs <see cref="DecodedAuthenticatorData" />.
    /// </summary>
    /// <param name="rpIdHash">
    ///     SHA-256 hash of the <a href="https://www.w3.org/TR/webauthn-3/#rp-id">RP ID</a>
    ///     the <a href="https://www.w3.org/TR/webauthn-3/#public-key-credential">credential</a> is <a href="https://www.w3.org/TR/webauthn-3/#scope">scoped</a> to.
    /// </param>
    /// <param name="flags"><a href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">Authenticator data</a> <a href="https://www.w3.org/TR/webauthn-3/#flags">flags</a>.</param>
    /// <param name="signCount"><a href="https://www.w3.org/TR/webauthn-3/#signature-counter">Signature counter</a>, 32-bit unsigned integer.</param>
    /// <param name="attestedCredentialData"><a href="https://www.w3.org/TR/webauthn-3/#attested-credential-data">Attested credential data</a> (if present).</param>
    /// <exception cref="ArgumentNullException"><paramref name="rpIdHash" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="flags" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException">The length of <paramref name="rpIdHash" /> is not equal to 32</exception>
    public DecodedAuthenticatorData(byte[] rpIdHash, IReadOnlySet<AuthenticatorDataFlags> flags, uint signCount, DecodedAttestedCredentialData? attestedCredentialData)
    {
        ArgumentNullException.ThrowIfNull(rpIdHash);
        ArgumentNullException.ThrowIfNull(flags);

        // 256 bits / 8 bits per byte = 32 bytes.
        if (rpIdHash.Length != 32)
        {
            throw new ArgumentException($"The value must contain exactly 32 bytes, in fact it contains: {rpIdHash.Length}.", nameof(rpIdHash));
        }

        RpIdHash = rpIdHash;
        Flags = flags;
        SignCount = signCount;
        AttestedCredentialData = attestedCredentialData;
    }

    /// <summary>
    ///     SHA-256 hash of the <a href="https://www.w3.org/TR/webauthn-3/#rp-id">RP ID</a>
    ///     the <a href="https://www.w3.org/TR/webauthn-3/#public-key-credential">credential</a> is <a href="https://www.w3.org/TR/webauthn-3/#scope">scoped</a> to.
    /// </summary>
    public byte[] RpIdHash { get; }

    /// <summary>
    ///     <a href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">Authenticator data</a> <a href="https://www.w3.org/TR/webauthn-3/#flags">flags</a>.
    /// </summary>
    public IReadOnlySet<AuthenticatorDataFlags> Flags { get; }

    /// <summary>
    ///     <a href="https://www.w3.org/TR/webauthn-3/#signature-counter">Signature counter</a>, 32-bit unsigned integer.
    /// </summary>
    public uint SignCount { get; }

    /// <summary>
    ///     <a href="https://www.w3.org/TR/webauthn-3/#attested-credential-data">Attested credential data</a> (if present).
    /// </summary>
    public DecodedAttestedCredentialData? AttestedCredentialData { get; }
}
