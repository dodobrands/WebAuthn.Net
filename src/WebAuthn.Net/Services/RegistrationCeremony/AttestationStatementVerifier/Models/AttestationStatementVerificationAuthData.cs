using System;
using System.Collections.Generic;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AuthenticatorData;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models.AttestationStatementVerifier;

/// <summary>
///     Representation of authenticator data used for 'attStmt' verification.
/// </summary>
public class AttestationStatementVerificationAuthData
{
    /// <summary>
    ///     Constructs <see cref="AttestationStatementVerificationAuthData" />.
    /// </summary>
    /// <param name="rpIdHash">
    ///     SHA-256 hash of the <a href="https://www.w3.org/TR/webauthn-3/#rp-id">RP ID</a>
    ///     the <a href="https://www.w3.org/TR/webauthn-3/#public-key-credential">credential</a> is <a href="https://www.w3.org/TR/webauthn-3/#scope">scoped</a> to.
    /// </param>
    /// <param name="flags"><a href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">Authenticator data</a> <a href="https://www.w3.org/TR/webauthn-3/#flags">flags</a>.</param>
    /// <param name="signCount"><a href="https://www.w3.org/TR/webauthn-3/#signature-counter">Signature counter</a>, 32-bit unsigned integer.</param>
    /// <param name="attestedCredentialData"><a href="https://www.w3.org/TR/webauthn-3/#attested-credential-data">Attested credential data</a> (if present).</param>
    /// <param name="rawAuthData">Raw value of authData.</param>
    /// <exception cref="ArgumentNullException"><paramref name="rpIdHash" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="flags" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="attestedCredentialData" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="rawAuthData" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException">The length of <paramref name="rpIdHash" /> is not equal to 32</exception>
    public AttestationStatementVerificationAuthData(
        byte[] rpIdHash,
        IReadOnlySet<AuthenticatorDataFlags> flags,
        uint signCount,
        DecodedAttestedCredentialData attestedCredentialData,
        byte[] rawAuthData)
    {
        ArgumentNullException.ThrowIfNull(rpIdHash);
        ArgumentNullException.ThrowIfNull(flags);
        ArgumentNullException.ThrowIfNull(attestedCredentialData);
        ArgumentNullException.ThrowIfNull(rawAuthData);

        // 256 bits / 8 bits per byte = 32 bytes.
        if (rpIdHash.Length != 32)
        {
            throw new ArgumentException($"The value must contain exactly 32 bytes, in fact it contains: {rpIdHash.Length}.", nameof(rpIdHash));
        }

        RpIdHash = rpIdHash;
        Flags = flags;
        SignCount = signCount;
        AttestedCredentialData = attestedCredentialData;
        RawAuthData = rawAuthData;
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
    public DecodedAttestedCredentialData AttestedCredentialData { get; }

    /// <summary>
    ///     Raw value of authData.
    /// </summary>
    public byte[] RawAuthData { get; }
}
