namespace WebAuthn.Net.Models.Enums;

/// <summary>
///     An enumeration indicating the current executing WebAuthn operation.
/// </summary>
public enum WebAuthnOperation
{
    /// <summary>
    ///     Beginning of the authentication ceremony (processing a request to generate options).
    /// </summary>
    BeginAuthenticationCeremony = 1,

    /// <summary>
    ///     Completion of the authentication ceremony (processing the result of the ceremony).
    /// </summary>
    CompleteAuthenticationCeremony = 2,

    /// <summary>
    ///     Beginning of the registration ceremony (processing a request to generate options).
    /// </summary>
    BeginRegistrationCeremony = 3,

    /// <summary>
    ///     Completion of the registration ceremony (processing the result of the ceremony).
    /// </summary>
    CompleteRegistrationCeremony = 4
}
