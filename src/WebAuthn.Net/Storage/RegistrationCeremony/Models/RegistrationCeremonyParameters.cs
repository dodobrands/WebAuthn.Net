using System;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;

namespace WebAuthn.Net.Storage.RegistrationCeremony.Models;

/// <summary>
///     Registration ceremony parameters.
/// </summary>
public class RegistrationCeremonyParameters
{
    /// <summary>
    ///     Constructs <see cref="RegistrationCeremonyParameters" />.
    /// </summary>
    /// <param name="options">Options for Credential Creation (dictionary PublicKeyCredentialCreationOptions)</param>
    /// <param name="expectedRp">Expected relying party parameters for the registration ceremony. Used to complete the registration ceremony.</param>
    /// <param name="createdAt">Creation date.</param>
    /// <param name="expiresAt">Expiration date.</param>
    public RegistrationCeremonyParameters(
        PublicKeyCredentialCreationOptions options,
        RegistrationCeremonyRpParameters expectedRp,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt)
    {
        Options = options;
        ExpectedRp = expectedRp;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    /// <summary>
    ///     Options for Credential Creation (dictionary PublicKeyCredentialCreationOptions)
    /// </summary>
    public PublicKeyCredentialCreationOptions Options { get; }

    /// <summary>
    ///     Expected relying party parameters for the registration ceremony. Used to complete the registration ceremony.
    /// </summary>
    public RegistrationCeremonyRpParameters ExpectedRp { get; }

    /// <summary>
    ///     Creation date.
    /// </summary>
    public DateTimeOffset CreatedAt { get; }

    /// <summary>
    ///     Expiration date.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; }
}
