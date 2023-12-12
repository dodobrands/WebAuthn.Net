using System;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.VerifyAssertion;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Models.VerifyAssertion;

/// <summary>
///     A request containing the parameters for completing the authentication ceremony
/// </summary>
public class CompleteAuthenticationCeremonyRequest
{
    /// <summary>
    ///     Constructs <see cref="CompleteAuthenticationCeremonyRequest" />.
    /// </summary>
    /// <param name="authenticationCeremonyId">Unique identifier of the authentication ceremony.</param>
    /// <param name="response">The result of performing the authentication ceremony serialized into a model suitable for JSON serialization in accordance with the rules described in the specification.</param>
    /// <exception cref="ArgumentNullException"><paramref name="authenticationCeremonyId" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException"><paramref name="authenticationCeremonyId" /> is empty</exception>
    /// <exception cref="ArgumentNullException"><paramref name="response" /> is <see langword="null" /></exception>
    public CompleteAuthenticationCeremonyRequest(string authenticationCeremonyId, AuthenticationResponseJSON response)
    {
        // authenticationCeremonyId
        ArgumentNullException.ThrowIfNull(authenticationCeremonyId);
        if (string.IsNullOrEmpty(authenticationCeremonyId))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(authenticationCeremonyId));
        }

        AuthenticationCeremonyId = authenticationCeremonyId;

        // response
        ArgumentNullException.ThrowIfNull(response);
        Response = response;
    }

    /// <summary>
    ///     Unique identifier of the authentication ceremony.
    /// </summary>
    public string AuthenticationCeremonyId { get; }

    /// <summary>
    ///     The result of performing the authentication ceremony serialized into a model suitable for JSON serialization in accordance with the rules described in the specification.
    /// </summary>
    public AuthenticationResponseJSON Response { get; }
}
