using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions.Protocol;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;

public class ExcludeCredentialsOptions
{
    public ExcludeCredentialsOptions(
        bool excludeAllExistingKeys,
        bool excludeManuallySpecified,
        PublicKeyCredentialDescriptor[]? manuallySpecifiedKeysToExclude)
    {
        ExcludeAllExistingKeys = excludeAllExistingKeys;
        ExcludeManuallySpecified = excludeManuallySpecified;
        ManuallySpecifiedKeysToExclude = manuallySpecifiedKeysToExclude;
    }

    public bool ExcludeAllExistingKeys { get; }

    [MemberNotNullWhen(true, nameof(ManuallySpecifiedKeysToExclude))]
    public bool ExcludeManuallySpecified { get; }

    public PublicKeyCredentialDescriptor[]? ManuallySpecifiedKeysToExclude { get; }

    public static ExcludeCredentialsOptions None()
    {
        return new(false, false, null);
    }

    public static ExcludeCredentialsOptions AllExisting()
    {
        return new(true, false, null);
    }

    public static ExcludeCredentialsOptions ManuallySpecified(PublicKeyCredentialDescriptor[] keysToExclude)
    {
        ArgumentNullException.ThrowIfNull(keysToExclude);
        return new(true, false, keysToExclude);
    }
}
