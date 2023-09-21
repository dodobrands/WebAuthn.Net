using System;
using System.ComponentModel;
using System.Linq;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models;

/// <summary>
///     Options for credential creation.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#dictionary-makecredentialoptions">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.4. Options for Credential Creation</a>
/// </remarks>
public class BeginCeremonyRequest
{
    /// <summary>
    ///     Constructs <see cref="BeginCeremonyRequest" />.
    /// </summary>
    /// <param name="challengeSize">
    ///     The size of the randomly generated <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-challenge">challenge</a> value.
    ///     <a href="https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges">The minimum allowed size is 16.</a>
    /// </param>
    /// <param name="rp">This member contains data about the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> responsible for the request.</param>
    /// <param name="user">This member contains data about the user account for which the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> is requesting attestation.</param>
    /// <param name="pubKeyCredParams">
    ///     This member contains information about the desired properties of the credential to be created.
    ///     The sequence is ordered from most preferred to least preferred.
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> makes a best-effort to create the most preferred credential that it can.
    /// </param>
    /// <param name="timeout">
    ///     This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
    ///     This is treated as a hint, and may be overridden by the <a href="https://www.w3.org/TR/webauthn-3/#client">client</a>.
    /// </param>
    /// <param name="excludeCredentials">
    ///     This member is intended for use by <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a>
    ///     that wish to limit the creation of multiple credentials for the same account on a single authenticator.
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> is requested to return an error
    ///     if the new credential would be created on an authenticator that also contains one of the credentials enumerated in this parameter.
    /// </param>
    /// <param name="authenticatorSelection">
    ///     This member is intended for use by <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a> that wish to select the appropriate authenticators
    ///     to participate in the <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-create">create()</a> operation.
    /// </param>
    /// <param name="attestation">
    ///     This member is intended for use by <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a> that wish to
    ///     express their preference for <a href="https://www.w3.org/TR/webauthn-3/#attestation-conveyance">attestation conveyance</a>.
    ///     Its values should be members of <see cref="AttestationConveyancePreference" />. Client platforms must ignore unknown values,
    ///     treating an unknown value as if the member does not exist. Its default value is <see cref="AttestationConveyancePreference.None" />.
    /// </param>
    /// <exception cref="ArgumentNullException">If <paramref name="rp" />, <paramref name="user" />, <paramref name="pubKeyCredParams" /> or <paramref name="excludeCredentials" /> is <see langword="null" />.</exception>
    /// <exception cref="ArgumentException">
    ///     If the value of the <paramref name="challengeSize" /> parameter is <a href="https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges">less than 16</a>.
    ///     If <paramref name="pubKeyCredParams" /> contains an empty array or if any of the elements in the <paramref name="pubKeyCredParams" /> array is <see langword="null" />.
    /// </exception>
    /// <exception cref="InvalidEnumArgumentException">If the <paramref name="attestation" /> parameter contains a value not defined in the <see cref="AttestationConveyancePreference" /> enum.</exception>
    public BeginCeremonyRequest(
        int challengeSize,
        PublicKeyCredentialRpEntity rp,
        PublicKeyCredentialUserEntity user,
        PublicKeyCredentialParameters[] pubKeyCredParams,
        uint? timeout,
        ExcludeCredentialsOptions excludeCredentials,
        AuthenticatorSelectionCriteria? authenticatorSelection,
        AttestationConveyancePreference? attestation)
    {
        ArgumentNullException.ThrowIfNull(rp);
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(pubKeyCredParams);
        ArgumentNullException.ThrowIfNull(excludeCredentials);
        if (challengeSize < 16)
        {
            throw new ArgumentException($"The minimum value of {nameof(challengeSize)} is 16.", nameof(challengeSize));
        }

        ChallengeSize = challengeSize;
        Rp = rp;
        User = user;
        if (pubKeyCredParams.Length == 0)
        {
            throw new ArgumentException("Value cannot be an empty collection.", nameof(pubKeyCredParams));
        }

        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (pubKeyCredParams.Any(static x => x is null))
        {
            throw new ArgumentException($"One or more objects contained in the {nameof(pubKeyCredParams)} array are equal to null.", nameof(pubKeyCredParams));
        }

        PubKeyCredParams = pubKeyCredParams;
        Timeout = timeout;
        ExcludeCredentials = excludeCredentials;
        AuthenticatorSelection = authenticatorSelection;
        if (attestation.HasValue)
        {
            if (!Enum.IsDefined(typeof(AttestationConveyancePreference), attestation.Value))
            {
                throw new InvalidEnumArgumentException(nameof(attestation), (int) attestation.Value, typeof(AttestationConveyancePreference));
            }

            Attestation = attestation.Value;
        }
    }

    /// <summary>
    ///     The size of the randomly generated <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-challenge">challenge</a> value.
    ///     <a href="https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges">The minimum allowed size is 16.</a>
    /// </summary>
    public int ChallengeSize { get; }

    /// <summary>
    ///     This member contains data about the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> responsible for the request.
    /// </summary>
    public PublicKeyCredentialRpEntity Rp { get; }

    /// <summary>
    ///     This member contains data about the user account for which the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> is requesting attestation.
    /// </summary>
    public PublicKeyCredentialUserEntity User { get; }

    /// <summary>
    ///     This member contains information about the desired properties of the credential to be created.
    ///     The sequence is ordered from most preferred to least preferred.
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> makes a best-effort to create the most preferred credential that it can.
    /// </summary>
    public PublicKeyCredentialParameters[] PubKeyCredParams { get; }

    /// <summary>
    ///     This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
    ///     This is treated as a hint, and may be overridden by the <a href="https://www.w3.org/TR/webauthn-3/#client">client</a>.
    /// </summary>
    public uint? Timeout { get; }

    /// <summary>
    ///     This member is intended for use by <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a>
    ///     that wish to limit the creation of multiple credentials for the same account on a single authenticator.
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> is requested to return an error
    ///     if the new credential would be created on an authenticator that also contains one of the credentials enumerated in this parameter.
    /// </summary>
    public ExcludeCredentialsOptions ExcludeCredentials { get; }

    /// <summary>
    ///     This member is intended for use by <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a> that wish to select the appropriate authenticators
    ///     to participate in the <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-create">create()</a> operation.
    /// </summary>
    public AuthenticatorSelectionCriteria? AuthenticatorSelection { get; }

    /// <summary>
    ///     This member is intended for use by <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a> that wish to
    ///     express their preference for <a href="https://www.w3.org/TR/webauthn-3/#attestation-conveyance">attestation conveyance</a>.
    ///     Its values should be members of <see cref="AttestationConveyancePreference" />. Client platforms must ignore unknown values,
    ///     treating an unknown value as if the member does not exist. Its default value is <see cref="AttestationConveyancePreference.None" />.
    /// </summary>
    public AttestationConveyancePreference? Attestation { get; }
}
