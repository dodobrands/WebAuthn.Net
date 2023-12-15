using System;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateCredential;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models.CreateCredential;

/// <summary>
///     Request containing parameters to complete the registration ceremony.
/// </summary>
public class CompleteRegistrationCeremonyRequest
{
    /// <summary>
    ///     Constructs <see cref="CompleteRegistrationCeremonyRequest" />.
    /// </summary>
    /// <param name="registrationCeremonyId">Unique identifier of the registration ceremony.</param>
    /// <param name="description">Description of the credential.</param>
    /// <param name="response">The result of performing the registration ceremony serialized into a model suitable for JSON serialization in accordance with the rules described in the specification.</param>
    /// <exception cref="ArgumentNullException"><paramref name="registrationCeremonyId" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException"><paramref name="registrationCeremonyId" /> is empty</exception>
    /// <exception cref="ArgumentNullException"><paramref name="response" /> is <see langword="null" /></exception>
    public CompleteRegistrationCeremonyRequest(
        string registrationCeremonyId,
        string? description,
        RegistrationResponseJSON response)
    {
        // registrationCeremonyId
        ArgumentNullException.ThrowIfNull(registrationCeremonyId);
        if (string.IsNullOrEmpty(registrationCeremonyId))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(registrationCeremonyId));
        }

        RegistrationCeremonyId = registrationCeremonyId;

        // description
        if (!string.IsNullOrWhiteSpace(description))
        {
            Description = description;
        }

        // response
        ArgumentNullException.ThrowIfNull(response);
        Response = response;
    }

    /// <summary>
    ///     Unique identifier of the registration ceremony.
    /// </summary>
    public string RegistrationCeremonyId { get; }

    /// <summary>
    ///     Description of the credential.
    /// </summary>
    public string? Description { get; }

    /// <summary>
    ///     The result of performing the registration ceremony serialized into a model suitable for JSON serialization in accordance with the rules described in the specification.
    /// </summary>
    public RegistrationResponseJSON Response { get; }
}
