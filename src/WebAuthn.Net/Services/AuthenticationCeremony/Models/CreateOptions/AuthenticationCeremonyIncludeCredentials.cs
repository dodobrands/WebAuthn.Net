using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models.Protocol;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;

public class AuthenticationCeremonyIncludeCredentials
{
    public AuthenticationCeremonyIncludeCredentials(
        bool includeAllExistingKeys,
        bool includeManuallySpecified,
        PublicKeyCredentialDescriptor[]? manuallySpecifiedKeysToInclude)
    {
        IncludeAllExistingKeys = includeAllExistingKeys;
        IncludeManuallySpecified = includeManuallySpecified;
        ManuallySpecifiedKeysToInclude = manuallySpecifiedKeysToInclude;
    }

    public bool IncludeAllExistingKeys { get; }

    [MemberNotNullWhen(true, nameof(ManuallySpecifiedKeysToInclude))]
    public bool IncludeManuallySpecified { get; }

    /// <summary>
    ///     The list is ordered in descending order of preference: the first item in the list is the most preferred credential, and the last is the least preferred.
    /// </summary>
    public PublicKeyCredentialDescriptor[]? ManuallySpecifiedKeysToInclude { get; }

    public static AuthenticationCeremonyIncludeCredentials None()
    {
        return new(false, false, null);
    }

    public static AuthenticationCeremonyIncludeCredentials AllExisting()
    {
        return new(true, false, null);
    }

    public static AuthenticationCeremonyIncludeCredentials ManuallySpecified(PublicKeyCredentialDescriptor[] keysToInclude)
    {
        ArgumentNullException.ThrowIfNull(keysToInclude);
        return new(true, false, keysToInclude);
    }
}
