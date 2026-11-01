using System;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions.Enums;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Models.VerifyAssertion;

/// <summary>
///     Result of successful completion of the authentication ceremony
/// </summary>
public class CompleteAuthenticationCeremonyResult
{
    /// <summary>
    ///     Constructs <see cref="CompleteAuthenticationCeremonyResult" />.
    /// </summary>
    /// <param name="recommendedActions">Actions recommended to be taken following a successful authentication ceremony, depending on the credential backup state.</param>
    /// <param name="userVerificationFlagMayBeUpdatedToTrue">
    ///     <para>
    ///         A flag referring to the <a href="https://www.w3.org/TR/webauthn-3/#authn-ceremony-update-credential-record">step of the authentication ceremony</a>: "If credentialRecord.uvInitialized is <see langword="false" />, update it to the value of the UV bit in the flags in
    ///         authData. This change SHOULD require authorization by an additional authentication factor equivalent to WebAuthn user verification; if not authorized, skip this step".
    ///     </para>
    ///     <para>
    ///         If the property contains <see langword="true" />, this means that during the authentication ceremony, it was established that the current stored value of credentialRecord.uvInitialized is <see langword="false" />, but the authenticator's response reported it has become
    ///         <see langword="true" />. According to the specification: "if not authorized, skip this step", therefore the library does NOT perform the updating of this specific credentialRecord property. If you need this step, implement it yourself.
    ///     </para>
    /// </param>
    /// <param name="userHandle">Identifier of the user account.</param>
    /// <param name="signCountNotIncreased">
    ///     <para>
    ///         <see langword="true" /> if the signature counter of the authenticator data ('authData.signCount') is less than or equal to the one stored in the credential record, although at least one of them is nonzero
    ///         (<a href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">step 22</a> of the authentication ceremony). This is a signal, but not proof, that the authenticator may be cloned: two or more copies of the credential private key
    ///         may exist and are being used in parallel, the authenticator may be malfunctioning, or the assertions may be processed in an order other than the order they were generated at the authenticator.
    ///     </para>
    ///     <para>
    ///         A ceremony with this signal completes only if <see cref="Configuration.Options.AuthenticationCeremonyOptions.AbortCeremonyWhenSignCountIsLessOrEqualStoredValue" /> is <see langword="false" /> (by default, it fails).
    ///         The stored signature counter then keeps its value, so the next assertions are compared with the highest one. The specification recommends incorporating this signal into the risk scoring of the Relying Party.
    ///     </para>
    /// </param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public CompleteAuthenticationCeremonyResult(
        CredentialBackupStateRecommendedAction[] recommendedActions,
        bool userVerificationFlagMayBeUpdatedToTrue,
        byte[] userHandle,
        bool signCountNotIncreased)
    {
        ArgumentNullException.ThrowIfNull(recommendedActions);
        ArgumentNullException.ThrowIfNull(userHandle);
        RecommendedActions = recommendedActions;
        UserVerificationFlagMayBeUpdatedToTrue = userVerificationFlagMayBeUpdatedToTrue;
        UserHandle = userHandle;
        SignCountNotIncreased = signCountNotIncreased;
    }

    /// <summary>
    ///     Actions recommended to be taken following a successful authentication ceremony, depending on the credential backup state.
    /// </summary>
    public CredentialBackupStateRecommendedAction[] RecommendedActions { get; }

    /// <summary>
    ///     <para>
    ///         A flag referring to the <a href="https://www.w3.org/TR/webauthn-3/#authn-ceremony-update-credential-record">step of the authentication ceremony</a>: "If credentialRecord.uvInitialized is <see langword="false" />, update it to the value of the UV bit in the flags in
    ///         authData. This change SHOULD require authorization by an additional authentication factor equivalent to WebAuthn user verification; if not authorized, skip this step".
    ///     </para>
    ///     <para>
    ///         If the property contains <see langword="true" />, this means that during the authentication ceremony, it was established that the current stored value of credentialRecord.uvInitialized is <see langword="false" />, but the authenticator's response reported it has become
    ///         <see langword="true" />. According to the specification: "if not authorized, skip this step", therefore the library does NOT perform the updating of this specific credentialRecord property. If you need this step, implement it yourself.
    ///     </para>
    /// </summary>
    public bool UserVerificationFlagMayBeUpdatedToTrue { get; }

    /// <summary>
    ///     Identifier of the user account.
    /// </summary>
    public byte[] UserHandle { get; }

    /// <summary>
    ///     <para>
    ///         <see langword="true" /> if the signature counter of the authenticator data ('authData.signCount') is less than or equal to the one stored in the credential record, although at least one of them is nonzero
    ///         (<a href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">step 22</a> of the authentication ceremony). This is a signal, but not proof, that the authenticator may be cloned: two or more copies of the credential private key
    ///         may exist and are being used in parallel, the authenticator may be malfunctioning, or the assertions may be processed in an order other than the order they were generated at the authenticator.
    ///     </para>
    ///     <para>
    ///         A ceremony with this signal completes only if <see cref="Configuration.Options.AuthenticationCeremonyOptions.AbortCeremonyWhenSignCountIsLessOrEqualStoredValue" /> is <see langword="false" /> (by default, it fails).
    ///         The stored signature counter then keeps its value, so the next assertions are compared with the highest one. The specification recommends incorporating this signal into the risk scoring of the Relying Party.
    ///     </para>
    /// </summary>
    public bool SignCountNotIncreased { get; }
}
