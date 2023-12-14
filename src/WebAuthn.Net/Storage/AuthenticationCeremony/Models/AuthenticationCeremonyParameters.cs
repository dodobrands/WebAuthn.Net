using System;
using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.CreateOptions;

namespace WebAuthn.Net.Storage.AuthenticationCeremony.Models;

/// <summary>
///     Authentication ceremony parameters.
/// </summary>
public class AuthenticationCeremonyParameters
{
    /// <summary>
    ///     Constructs <see cref="AuthenticationCeremonyParameters" />.
    /// </summary>
    /// <param name="userHandle">Unique identifier for the user account.</param>
    /// <param name="options">Options for Assertion Generation (dictionary PublicKeyCredentialRequestOptions).</param>
    /// <param name="expectedRp">Expected relying party parameters for the authentication ceremony. Used to complete the authentication ceremony.</param>
    /// <param name="createdAt">Creation date.</param>
    /// <param name="expiresAt">Expiration date.</param>
    public AuthenticationCeremonyParameters(
        byte[]? userHandle,
        PublicKeyCredentialRequestOptions options,
        AuthenticationCeremonyRpParameters expectedRp,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt)
    {
        UserHandle = userHandle;
        Options = options;
        ExpectedRp = expectedRp;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    /// <summary>
    ///     Unique identifier for the user account.
    /// </summary>
    public byte[]? UserHandle { get; }

    /// <summary>
    ///     Options for Assertion Generation (dictionary PublicKeyCredentialRequestOptions).
    /// </summary>
    public PublicKeyCredentialRequestOptions Options { get; }

    /// <summary>
    ///     Expected relying party parameters for the authentication ceremony. Used to complete the authentication ceremony.
    /// </summary>
    public AuthenticationCeremonyRpParameters ExpectedRp { get; }

    /// <summary>
    ///     Creation date.
    /// </summary>
    public DateTimeOffset CreatedAt { get; }

    /// <summary>
    ///     Expiration date.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; }
}
