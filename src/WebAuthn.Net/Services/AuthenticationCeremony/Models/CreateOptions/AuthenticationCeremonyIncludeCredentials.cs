using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.CreateOptions;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;

/// <summary>
///     Parameters for including credentials in the authentication ceremony. Defines which credentials will be included in <see cref="PublicKeyCredentialRequestOptions" />.<see cref="PublicKeyCredentialRequestOptions.AllowCredentials" />.
/// </summary>
public class AuthenticationCeremonyIncludeCredentials
{
    /// <summary>
    ///     Constructs <see cref="AuthenticationCeremonyIncludeCredentials" />.
    /// </summary>
    /// <param name="includeAllExistingKeys">Include all existing keys.</param>
    /// <param name="includeManuallySpecified">Include only keys specified manually.</param>
    /// <param name="manuallySpecifiedKeysToInclude">The list is ordered in descending order of preference: the first item in the list is the most preferred credential, and the last is the least preferred.</param>
    public AuthenticationCeremonyIncludeCredentials(
        bool includeAllExistingKeys,
        bool includeManuallySpecified,
        PublicKeyCredentialDescriptor[]? manuallySpecifiedKeysToInclude)
    {
        IncludeAllExistingKeys = includeAllExistingKeys;
        IncludeManuallySpecified = includeManuallySpecified;
        ManuallySpecifiedKeysToInclude = manuallySpecifiedKeysToInclude;
    }

    /// <summary>
    ///     <para>Include all existing keys. It's important that only keys for the current rpId and <see cref="BeginAuthenticationCeremonyRequest.UserHandle" /> will be included.</para>
    ///     <para>
    ///         If <see cref="BeginAuthenticationCeremonyRequest.UserHandle" /> is not set - keys will not be included. Importantly, in this case, only <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credentials</a> will be utilized in
    ///         this authentication ceremony.
    ///     </para>
    ///     <para>If this parameter is <see langword="true" />, then the other parameters are ignored.</para>
    /// </summary>
    public bool IncludeAllExistingKeys { get; }

    /// <summary>
    ///     <para>
    ///         Include only keys specified manually. It's important in this case to specify a <see cref="BeginAuthenticationCeremonyRequest.UserHandle" />, as a check will be performed for the presence of such keys for the <see cref="BeginAuthenticationCeremonyRequest.UserHandle" />
    ///         and rpId combination.
    ///     </para>
    ///     <para>
    ///         During the check, the <see cref="PublicKeyCredentialDescriptor.Transports" /> value for the specified keys is also compared. It should be equal to, or contain fewer values than in the stored credential. If <see cref="PublicKeyCredentialDescriptor.Transports" /> are not
    ///         specified in the stored credential, they should not be indicated for such a credential in the list of manually specified keys (otherwise, it will be skipped and won't be included in the final list of allowed credentials).
    ///     </para>
    ///     <para>
    ///         If the <see cref="BeginAuthenticationCeremonyRequest.UserHandle" /> is not set or keys with the specified descriptors are not found - keys will not be included. Importantly, in this case, only
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credentials</a> will be utilized in this authentication ceremony.
    ///     </para>
    ///     <para>If this parameter is true, then <see cref="ManuallySpecifiedKeysToInclude" /> must not be null (it can contain an empty array, but not <see langword="null" />).</para>
    ///     <para>This parameter will be applied only if <see cref="BeginAuthenticationCeremonyRequest.UserHandle" /> contains a value, and <see cref="IncludeAllExistingKeys" /> is set to <see langword="false" />.</para>
    /// </summary>
    [MemberNotNullWhen(true, nameof(ManuallySpecifiedKeysToInclude))]
    public bool IncludeManuallySpecified { get; }

    /// <summary>
    ///     <para>The list is ordered in descending order of preference: the first item in the list is the most preferred credential, and the last is the least preferred.</para>
    ///     <para>Will be used only if <see cref="IncludeManuallySpecified" /> is in use, and its value is set to <see langword="true" />. In such a case, the value of this property should not be <see langword="null" />.</para>
    /// </summary>
    public PublicKeyCredentialDescriptor[]? ManuallySpecifiedKeysToInclude { get; }

    /// <summary>
    ///     Creates such parameters for including credentials in the authentication ceremony, indicating that there is no need to include any values in the list of allowable keys.
    /// </summary>
    public static AuthenticationCeremonyIncludeCredentials None()
    {
        return new(false, false, null);
    }

    /// <summary>
    ///     Creates inclusion parameters for credentials in the authentication ceremony, indicating that all known credentials need to be included.
    /// </summary>
    public static AuthenticationCeremonyIncludeCredentials AllExisting()
    {
        return new(true, false, null);
    }

    /// <summary>
    ///     Creates inclusion parameters for credentials in the authentication ceremony, indicating that only specific credentials need to be included.
    /// </summary>
    /// <param name="keysToInclude">Descriptors of keys that need to be included in the authentication ceremony. Can be an empty array, cannot be <see langword="null" />.</param>
    /// <exception cref="ArgumentNullException"><paramref name="keysToInclude" /> is <see langword="null" /></exception>
    public static AuthenticationCeremonyIncludeCredentials ManuallySpecified(PublicKeyCredentialDescriptor[] keysToInclude)
    {
        ArgumentNullException.ThrowIfNull(keysToInclude);
        return new(true, false, keysToInclude);
    }
}
