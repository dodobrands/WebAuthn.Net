using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;

/// <summary>
///     Parameters defining how to form <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-excludecredentials">excludeCredentials</a> in the
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-makecredentialoptions">registration ceremony options</a>.
/// </summary>
public class RegistrationCeremonyExcludeCredentials
{
    /// <summary>
    ///     Constructs <see cref="RegistrationCeremonyExcludeCredentials" />.
    /// </summary>
    /// <param name="excludeAllExistingKeys">Exclude all existing keys.</param>
    /// <param name="excludeManuallySpecified">Flag indicating that only manually specified keys need to be excluded.</param>
    /// <param name="manuallySpecifiedKeysToExclude">Array of manually specified key descriptors to be excluded from the registration ceremony.</param>
    public RegistrationCeremonyExcludeCredentials(
        bool excludeAllExistingKeys,
        bool excludeManuallySpecified,
        RegistrationCeremonyPublicKeyCredentialDescriptor[]? manuallySpecifiedKeysToExclude)
    {
        ExcludeAllExistingKeys = excludeAllExistingKeys;
        ExcludeManuallySpecified = excludeManuallySpecified;
        ManuallySpecifiedKeysToExclude = manuallySpecifiedKeysToExclude;
    }

    /// <summary>
    ///     <para>Exclude all existing keys.</para>
    ///     <para>It's important that only keys for the current rpId and <see cref="PublicKeyCredentialUserEntity" />.<see cref="PublicKeyCredentialUserEntity.Id" /> will be excluded.</para>
    ///     <para>If this parameter is <see langword="true" />, then the other parameters are ignored.</para>
    /// </summary>
    public bool ExcludeAllExistingKeys { get; }

    /// <summary>
    ///     <para>Flag indicating that only manually specified keys need to be excluded.</para>
    ///     <para>It's important that only keys for the current rpId and <see cref="PublicKeyCredentialUserEntity" />.<see cref="PublicKeyCredentialUserEntity.Id" /> will be excluded.</para>
    ///     <para>If this parameter is <see langword="true" />, then <see cref="ManuallySpecifiedKeysToExclude" /> must not be <see langword="null" /> (it can be an empty array, but not <see langword="null" />).</para>
    ///     <para>It only matters if <see cref="ExcludeAllExistingKeys" /> is <see langword="false" />.</para>
    /// </summary>
    [MemberNotNullWhen(true, nameof(ManuallySpecifiedKeysToExclude))]
    public bool ExcludeManuallySpecified { get; }

    /// <summary>
    ///     <para>Array of manually specified key descriptors to be excluded from the registration ceremony.</para>
    ///     <para>It only matters if <see cref="ExcludeAllExistingKeys" /> is <see langword="false" />, and <see cref="ExcludeManuallySpecified" /> is <see langword="true" />.</para>
    ///     <para>If <see cref="ExcludeManuallySpecified" /> is <see langword="true" />, then it must not be <see langword="null" /> (it can contain an empty array, but not <see langword="null" />). In other cases, it can be <see langword="null" />.</para>
    ///     <para>It's important that only keys for the current rpId and <see cref="PublicKeyCredentialUserEntity" />.<see cref="PublicKeyCredentialUserEntity.Id" /> will be excluded.</para>
    /// </summary>
    public RegistrationCeremonyPublicKeyCredentialDescriptor[]? ManuallySpecifiedKeysToExclude { get; }

    /// <summary>
    ///     <para>Creates parameters indicating that no exclusion of any key descriptors is required for the registration ceremony.</para>
    ///     <para>
    ///         In this case, <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-excludecredentials">excludeCredentials</a> in the resulting
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-makecredentialoptions">registration ceremony options</a> will be <see langword="null" />.
    ///     </para>
    /// </summary>
    /// <returns>An instance of <see cref="RegistrationCeremonyExcludeCredentials" />, containing such a combination of properties that indicates no exclusion of any key descriptors is required for the registration ceremony.</returns>
    public static RegistrationCeremonyExcludeCredentials None()
    {
        return new(false, false, null);
    }

    /// <summary>
    ///     Creates parameters indicating that all registered keys should be excluded from the registration ceremony.
    /// </summary>
    /// <returns>An instance of <see cref="RegistrationCeremonyExcludeCredentials" />, containing a combination of parameters that will indicate that all previously registered keys need to be excluded from the registration ceremony. </returns>
    public static RegistrationCeremonyExcludeCredentials AllExisting()
    {
        return new(true, false, null);
    }

    /// <summary>
    ///     Creates parameters indicating that only specific descriptors of previously registered keys need to be excluded from the registration ceremony
    /// </summary>
    /// <param name="keysToExclude">Keys that need to be excluded from the registration ceremony.</param>
    /// <returns>An instance of <see cref="RegistrationCeremonyExcludeCredentials" />, containing a combination of parameters that will indicate that only specific previously registered keys need to be excluded from the registration ceremony.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="keysToExclude" /> is <see langword="null" /></exception>
    public static RegistrationCeremonyExcludeCredentials ManuallySpecified(RegistrationCeremonyPublicKeyCredentialDescriptor[] keysToExclude)
    {
        ArgumentNullException.ThrowIfNull(keysToExclude);
        return new(false, true, keysToExclude);
    }
}
