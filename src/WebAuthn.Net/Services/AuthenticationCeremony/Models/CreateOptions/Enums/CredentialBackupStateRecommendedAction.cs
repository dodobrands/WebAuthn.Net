namespace WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions.Enums;

/// <summary>
///     Actions recommended to be taken depending on the credential backup state.
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-credential-backup">Web Authentication: An API for accessing Public Key Credentials Level 3 - §6.1.3. Credential Backup State</a>
///     </para>
/// </remarks>
public enum CredentialBackupStateRecommendedAction
{
    /// <summary>
    ///     <para>Requiring additional authenticators</para>
    ///     <para>
    ///         When the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-be">BE</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flag</a> is set to 0, the credential is a
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#single-device-credential">single-device credential</a> and the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#generating-authenticator">generating authenticator</a> will never allow the credential
    ///         to be backed up.
    ///     </para>
    ///     <para>
    ///         A <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#single-device-credential">single-device credential</a> is not resilient to single device loss. <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> SHOULD ensure
    ///         that each <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> has additional <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticators</a>
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration-ceremony">registered</a> and/or an account recovery process in place. For example, the user could be prompted to set up an additional
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>, such as a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#roaming-authenticators">roaming authenticator</a> or an
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> that is capable of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#multi-device-credential">multi-device credentials</a>.
    ///     </para>
    /// </summary>
    RequiringAdditionalAuthenticators = 1,

    /// <summary>
    ///     <para>Upgrading a user to a password-free account</para>
    ///     <para>
    ///         When the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-bs">BS</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flag</a> changes from 0 to 1, the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> is signaling that the <a href="https://www.w3.org/TR/credential-management-1/#concept-credential">credential</a> is backed up and is protected from single device loss
    ///     </para>
    ///     <para>The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY choose to prompt the user to upgrade their account security and remove their password.</para>
    /// </summary>
    UpgradingUserToPasswordlessAccount = 2,

    /// <summary>
    ///     <para>Adding an additional factor after a state change</para>
    ///     <para>
    ///         When the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-bs">BS</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flag</a> changes from 1 to 0, the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> is signaling that the <a href="https://www.w3.org/TR/credential-management-1/#concept-credential">credential</a> is no longer backed up, and no longer protected from single
    ///         device loss. This could be the result of the user actions, such as disabling the backup service, or errors, such as issues with the backup service.
    ///     </para>
    ///     <para>
    ///         When this transition occurs, the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD guide the user through a process to validate their other authentication factors. If the user does not have another credential for their
    ///         account, they SHOULD be guided through adding an additional credential to ensure they do not lose access to their account. For example, the user could be prompted to set up an additional
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>, such as a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#roaming-authenticators">roaming authenticator</a> or an
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> that is capable of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#multi-device-credential">multi-device credentials</a>.
    ///     </para>
    /// </summary>
    AddingAdditionalFactorAfterStateChange = 3
}
