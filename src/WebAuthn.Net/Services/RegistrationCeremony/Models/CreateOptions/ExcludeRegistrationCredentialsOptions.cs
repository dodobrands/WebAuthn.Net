using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions.Protocol;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;

public class ExcludeRegistrationCredentialsOptions
{
    public ExcludeRegistrationCredentialsOptions(
        bool excludeAllExistingKeys,
        bool excludeManuallySpecified,
        RegistrationPublicKeyCredentialDescriptor[]? manuallySpecifiedKeysToExclude)
    {
        ExcludeAllExistingKeys = excludeAllExistingKeys;
        ExcludeManuallySpecified = excludeManuallySpecified;
        ManuallySpecifiedKeysToExclude = manuallySpecifiedKeysToExclude;
    }

    public bool ExcludeAllExistingKeys { get; }

    [MemberNotNullWhen(true, nameof(ManuallySpecifiedKeysToExclude))]
    public bool ExcludeManuallySpecified { get; }

    public RegistrationPublicKeyCredentialDescriptor[]? ManuallySpecifiedKeysToExclude { get; }

    public static ExcludeRegistrationCredentialsOptions None()
    {
        return new(false, false, null);
    }

    public static ExcludeRegistrationCredentialsOptions AllExisting()
    {
        return new(true, false, null);
    }

    public static ExcludeRegistrationCredentialsOptions ManuallySpecified(RegistrationPublicKeyCredentialDescriptor[] keysToExclude)
    {
        ArgumentNullException.ThrowIfNull(keysToExclude);
        return new(true, false, keysToExclude);
    }
}
