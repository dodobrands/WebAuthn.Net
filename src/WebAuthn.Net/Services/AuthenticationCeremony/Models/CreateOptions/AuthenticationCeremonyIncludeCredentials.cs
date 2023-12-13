using System;
using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;

/// <summary>
///     Parameters defining how to form <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialrequestoptions-allowcredentials">allowCredentials</a> in the
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-assertion-options">authentication ceremony options</a>.
/// </summary>
public class AuthenticationCeremonyIncludeCredentials
{
    /// <summary>
    ///     Constructs <see cref="AuthenticationCeremonyIncludeCredentials" />.
    /// </summary>
    /// <param name="includeAllExistingKeys">Include all existing keys.</param>
    /// <param name="includeManuallySpecified">Include only keys specified manually.</param>
    /// <param name="manuallySpecifiedKeysToInclude">Array of manually specified key descriptors in descending order of preference: the first item in the array is the most preferred credential, and the last is the least preferred.</param>
    public AuthenticationCeremonyIncludeCredentials(
        bool includeAllExistingKeys,
        bool includeManuallySpecified,
        AuthenticationCeremonyPublicKeyCredentialDescriptor[]? manuallySpecifiedKeysToInclude)
    {
        IncludeAllExistingKeys = includeAllExistingKeys;
        IncludeManuallySpecified = includeManuallySpecified;
        ManuallySpecifiedKeysToInclude = manuallySpecifiedKeysToInclude;
    }


    /// <summary>
    ///     <para>Include all existing keys.</para>
    ///     <para>It's important that only keys for the current rpId and <see cref="BeginAuthenticationCeremonyRequest.UserHandle" /> will be included.</para>
    ///     <para>
    ///         If <see cref="BeginAuthenticationCeremonyRequest.UserHandle" /> is not set, then no keys will be included and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialrequestoptions-allowcredentials">allowCredentials</a> in the resulting
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-assertion-options">authentication ceremony options</a> will be <see langword="null" />. It's important that in this case the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> will use only <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credentials (Passkeys)</a> in the process of the authentication ceremony.
    ///     </para>
    ///     <para>If this parameter is <see langword="true" />, then the other parameters are ignored.</para>
    /// </summary>
    public bool IncludeAllExistingKeys { get; }

    /// <summary>
    ///     <para>Flag indicating that only manually specified keys need to be included.</para>
    ///     <para>It's important that only keys for the current rpId and <see cref="BeginAuthenticationCeremonyRequest.UserHandle" /> will be included.</para>
    ///     <para>
    ///         If <see cref="BeginAuthenticationCeremonyRequest.UserHandle" /> is not set, then no keys will be included and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialrequestoptions-allowcredentials">allowCredentials</a> in the resulting
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-assertion-options">authentication ceremony options</a> will be <see langword="null" />. It's important that in this case the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> will use only <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credentials (Passkeys)</a> in the process of the authentication ceremony.
    ///     </para>
    ///     <para>If this parameter is <see langword="true" />, then <see cref="ManuallySpecifiedKeysToInclude" /> must not be must not be <see langword="null" /> (it can be an empty array, but not <see langword="null" />).</para>
    ///     <para>It only matters if <see cref="IncludeAllExistingKeys" /> is <see langword="false" />.</para>
    /// </summary>
    [MemberNotNullWhen(true, nameof(ManuallySpecifiedKeysToInclude))]
    public bool IncludeManuallySpecified { get; }

    /// <summary>
    ///     <para>Array of manually specified key descriptors that should be included in the authentication ceremony.</para>
    ///     <para>It only matters if <see cref="IncludeAllExistingKeys" /> is <see langword="false" />, and <see cref="IncludeManuallySpecified" /> is <see langword="true" />.</para>
    ///     <para>If <see cref="IncludeManuallySpecified" /> is <see langword="true" />, then it must not be <see langword="null" /> (it can contain an empty array, but not <see langword="null" />). In other cases, it can be <see langword="null" />.</para>
    ///     <para>It's important that only keys for the current rpId and <see cref="BeginAuthenticationCeremonyRequest.UserHandle" /> will be included.</para>
    /// </summary>
    public AuthenticationCeremonyPublicKeyCredentialDescriptor[]? ManuallySpecifiedKeysToInclude { get; }

    /// <summary>
    ///     <para>Creates parameters that indicate that no key descriptors need to be included for the authentication ceremony.</para>
    ///     <para>
    ///         In this case, <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialrequestoptions-allowcredentials">allowCredentials</a> in the resulting
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-assertion-options">authentication ceremony options</a> will be <see langword="null" />. This means that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> will only be
    ///         able to use <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credentials (Passkeys)</a> during the authentication ceremony.
    ///     </para>
    /// </summary>
    /// <returns>An instance of <see cref="AuthenticationCeremonyIncludeCredentials" />, containing a combination of properties that indicates no key descriptors need to be included for the authentication ceremony.</returns>
    public static AuthenticationCeremonyIncludeCredentials None()
    {
        return new(false, false, null);
    }

    /// <summary>
    ///     Creates parameters indicating that all registered keys should be included in the authentication ceremony.
    /// </summary>
    /// <returns>An instance of <see cref="AuthenticationCeremonyIncludeCredentials" />, containing a combination of parameters that will indicate that all previously registered keys need to be included in the authentication ceremony.</returns>
    public static AuthenticationCeremonyIncludeCredentials AllExisting()
    {
        return new(true, false, null);
    }

    /// <summary>
    ///     Creates parameters indicating that only specific descriptors of previously registered keys need to be included in the authentication ceremony.
    /// </summary>
    /// <param name="keysToInclude">Keys that need to be included in the authentication ceremony.</param>
    /// <returns>An instance of <see cref="AuthenticationCeremonyIncludeCredentials" />, containing a combination of parameters that will indicate that only specific previously registered keys need to be included in the authentication ceremony.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="keysToInclude" /> is <see langword="null" /></exception>
    public static AuthenticationCeremonyIncludeCredentials ManuallySpecified(AuthenticationCeremonyPublicKeyCredentialDescriptor[] keysToInclude)
    {
        ArgumentNullException.ThrowIfNull(keysToInclude);
        return new(true, false, keysToInclude);
    }
}
