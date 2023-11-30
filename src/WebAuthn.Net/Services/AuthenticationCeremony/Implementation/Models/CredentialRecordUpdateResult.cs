using System;
using WebAuthn.Net.Storage.Credential.Models;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Implementation.Models;

/// <summary>
///     The result of updating the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">credentialRecord</a>.
/// </summary>
public class CredentialRecordUpdateResult
{
    /// <summary>
    ///     Constructs <see cref="CredentialRecordUpdateResult" />.
    /// </summary>
    /// <param name="updatedCredentialRecord">The updated value of the credentialRecord.</param>
    /// <param name="userVerificationFlagMayBeUpdatedToTrue">
    ///     <para>
    ///         A flag referring to the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authn-ceremony-update-credential-record">26.3 step of the authentication ceremony</a>: "If credentialRecord.
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#abstract-opdef-credential-record-uvinitialized">uvInitialized</a> is <see langword="false" />, update it to the value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-uv">UV</a>
    ///         bit in the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flags</a> in authData. This change SHOULD require authorization by an additional <a href="https://pages.nist.gov/800-63-3/sp800-63-3.html#af">authentication factor</a> equivalent to
    ///         WebAuthn <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a>; if not authorized, skip this step.".
    ///     </para>
    ///     <para>
    ///         If the property contains <see langword="true" />, this means that during the authentication ceremony, it was established that the current stored value of credentialRecord.uvInitialized is <see langword="false" />, but the authenticator's response reported it has become
    ///         <see langword="true" />. According to the specification: "if not authorized, skip this step", therefore the library does NOT perform the updating of this specific credentialRecord property. If you need this step, implement it yourself.
    ///     </para>
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="updatedCredentialRecord" /> is <see langword="null" /></exception>
    public CredentialRecordUpdateResult(CredentialRecord updatedCredentialRecord, bool userVerificationFlagMayBeUpdatedToTrue)
    {
        ArgumentNullException.ThrowIfNull(updatedCredentialRecord);
        UpdatedCredentialRecord = updatedCredentialRecord;
        UserVerificationFlagMayBeUpdatedToTrue = userVerificationFlagMayBeUpdatedToTrue;
    }

    /// <summary>
    ///     The updated value of the credentialRecord.
    /// </summary>
    public CredentialRecord UpdatedCredentialRecord { get; }

    /// <summary>
    ///     <para>
    ///         A flag referring to the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authn-ceremony-update-credential-record">26.3 step of the authentication ceremony</a>: "If credentialRecord.
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#abstract-opdef-credential-record-uvinitialized">uvInitialized</a> is <see langword="false" />, update it to the value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags-uv">UV</a>
    ///         bit in the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-flags">flags</a> in authData. This change SHOULD require authorization by an additional <a href="https://pages.nist.gov/800-63-3/sp800-63-3.html#af">authentication factor</a> equivalent to
    ///         WebAuthn <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a>; if not authorized, skip this step.".
    ///     </para>
    ///     <para>
    ///         If the property contains <see langword="true" />, this means that during the authentication ceremony, it was established that the current stored value of credentialRecord.uvInitialized is <see langword="false" />, but the authenticator's response reported it has become
    ///         <see langword="true" />. According to the specification: "if not authorized, skip this step", therefore the library does NOT perform the updating of this specific credentialRecord property. If you need this step, implement it yourself.
    ///     </para>
    /// </summary>
    public bool UserVerificationFlagMayBeUpdatedToTrue { get; }
}
