using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using WebAuthn.Net.Models.Protocol;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models;

public class ExcludeCredentialsOptions
{
    public ExcludeCredentialsOptions(
        bool excludeAllExistingKeys,
        bool excludeSpecificKeys,
        PublicKeyCredentialDescriptor[]? specificKeysToExclude)
    {
        ExcludeAllExistingKeys = excludeAllExistingKeys;
        ExcludeSpecificKeys = excludeSpecificKeys;
        SpecificKeysToExclude = specificKeysToExclude;
    }

    public bool ExcludeAllExistingKeys { get; }

    [MemberNotNullWhen(true, nameof(SpecificKeysToExclude))]
    public bool ExcludeSpecificKeys { get; }

    public PublicKeyCredentialDescriptor[]? SpecificKeysToExclude { get; }

    public static ExcludeCredentialsOptions None()
    {
        return new(false, false, null);
    }

    public static ExcludeCredentialsOptions AllExisting()
    {
        return new(true, false, null);
    }

    public static ExcludeCredentialsOptions SpecificKeys(PublicKeyCredentialDescriptor[] keysToExclude)
    {
        ArgumentNullException.ThrowIfNull(keysToExclude);
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (keysToExclude.Any(static x => x is null))
        {
            throw new ArgumentException($"One or more objects contained in the {nameof(keysToExclude)} array are equal to null.", nameof(keysToExclude));
        }

        return new(true, false, keysToExclude);
    }
}
