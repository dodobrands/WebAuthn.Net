using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models.Protocol;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;

public class RegistrationCeremonyExcludeCredentials
{
    public RegistrationCeremonyExcludeCredentials(bool excludeAllExistingKeys)
    {
        ExcludeAllExistingKeys = excludeAllExistingKeys;
        ExcludeManuallySpecified = false;
        ManuallySpecifiedKeysToExclude = null;
    }

    public RegistrationCeremonyExcludeCredentials(PublicKeyCredentialDescriptor[] manuallySpecifiedKeysToExclude)
    {
        ArgumentNullException.ThrowIfNull(manuallySpecifiedKeysToExclude);
        ExcludeAllExistingKeys = false;
        ExcludeManuallySpecified = true;
        ManuallySpecifiedKeysToExclude = manuallySpecifiedKeysToExclude;
    }

    public bool ExcludeAllExistingKeys { get; }

    [MemberNotNullWhen(true, nameof(ManuallySpecifiedKeysToExclude))]
    public bool ExcludeManuallySpecified { get; }

    public PublicKeyCredentialDescriptor[]? ManuallySpecifiedKeysToExclude { get; }

    public static RegistrationCeremonyExcludeCredentials None()
    {
        return new(false);
    }

    public static RegistrationCeremonyExcludeCredentials AllExisting()
    {
        return new(true);
    }

    public static RegistrationCeremonyExcludeCredentials ManuallySpecified(PublicKeyCredentialDescriptor[] keysToExclude)
    {
        ArgumentNullException.ThrowIfNull(keysToExclude);
        return new(keysToExclude);
    }
}
