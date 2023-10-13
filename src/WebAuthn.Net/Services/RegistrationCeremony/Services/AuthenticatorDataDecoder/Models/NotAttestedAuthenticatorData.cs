﻿using System;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AuthenticatorDataDecoder.Models.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AuthenticatorDataDecoder.Models.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AuthenticatorDataDecoder.Models;

/// <summary>
///     Authenticator Data (which does not have attestedCredentialData).
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-data">Web Authentication: An API for accessing Public Key Credentials Level 3 - §6.1. Authenticator Data</a>
/// </remarks>
public class NotAttestedAuthenticatorData : AbstractAuthenticatorData
{
    /// <summary>
    ///     Constructs <see cref="NotAttestedAuthenticatorData" />.
    /// </summary>
    /// <param name="raw">Raw <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-data">authenticator data</a> value.</param>
    /// <param name="rpIdHash">
    ///     SHA-256 hash of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#rp-id">RP ID</a> the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">credential</a> is
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#scope"></a>scoped to.
    /// </param>
    /// <param name="flags"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-data">Authenticator data</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flags</a>.</param>
    /// <param name="signCount"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#signature-counter">Signature counter</a>, 32-bit unsigned integer.</param>
    /// <exception cref="ArgumentNullException"><paramref name="raw" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="rpIdHash" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException">The length of <paramref name="rpIdHash" /> is not equal to 32</exception>
    public NotAttestedAuthenticatorData(
        byte[] raw,
        byte[] rpIdHash,
        AuthenticatorDataFlags flags,
        uint signCount)
    {
        // raw
        ArgumentNullException.ThrowIfNull(raw);
        Raw = raw;

        // rpIdHash
        ArgumentNullException.ThrowIfNull(rpIdHash);
        if (rpIdHash.Length != 32)
        {
            // rpIdHash is SHA-256 hash
            // 256 bits / 8 bits per byte = 32 bytes.
            throw new ArgumentException($"The value must contain exactly 32 bytes, in fact it contains: {rpIdHash.Length}.", nameof(rpIdHash));
        }

        RpIdHash = rpIdHash;

        // flags
        Flags = flags;

        // signCount
        SignCount = signCount;
    }

    /// <inheritdoc />
    public override byte[] Raw { get; }

    /// <inheritdoc />
    public override byte[] RpIdHash { get; }

    /// <inheritdoc />
    public override AuthenticatorDataFlags Flags { get; }

    /// <inheritdoc />
    public override uint SignCount { get; }
}
