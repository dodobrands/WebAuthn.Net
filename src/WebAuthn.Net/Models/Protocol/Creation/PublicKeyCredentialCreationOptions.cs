using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text.Json.Serialization;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Models.Protocol.Creation;

/// <summary>
///     Options for credential creation.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#dictionary-makecredentialoptions">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.4. Options for Credential Creation</a>
/// </remarks>
public class PublicKeyCredentialCreationOptions
{
    public PublicKeyCredentialCreationOptions(
        PublicKeyCredentialRpEntity rp,
        PublicKeyCredentialUserEntity user,
        byte[] challenge,
        PublicKeyCredentialParameters[] pubKeyCredParams,
        uint? timeout,
        PublicKeyCredentialDescriptor[]? excludeCredentials,
        AuthenticatorSelectionCriteria? authenticatorSelection,
        AttestationConveyancePreference? attestation,
        AuthenticationExtensionsClientInputs? extensions)
    {
        ArgumentNullException.ThrowIfNull(rp);
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(pubKeyCredParams);
        Rp = rp;
        User = user;
        var challengeCopy = new byte[challenge.Length];
        challenge.CopyTo(challengeCopy, 0);
        Challenge = challengeCopy;
        if (pubKeyCredParams.Length == 0)
        {
            throw new ArgumentException("Value cannot be an empty collection.", nameof(pubKeyCredParams));
        }

        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (pubKeyCredParams.Any(static x => x is null))
        {
            throw new ArgumentException($"One or more objects contained in the {nameof(pubKeyCredParams)} array are equal to null.", nameof(pubKeyCredParams));
        }

        var pubKeyCredParamsCopy = new PublicKeyCredentialParameters[pubKeyCredParams.Length];
        pubKeyCredParams.CopyTo(pubKeyCredParamsCopy, 0);
        PubKeyCredParams = pubKeyCredParamsCopy;
        Timeout = timeout;
        if (excludeCredentials?.Length > 0)
        {
            // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
            if (excludeCredentials.Any(static x => x is null))
            {
                throw new ArgumentException($"One or more objects contained in the {nameof(excludeCredentials)} array are equal to null.", nameof(excludeCredentials));
            }

            var excludeCredentialsCopy = new PublicKeyCredentialDescriptor[excludeCredentials.Length];
            excludeCredentials.CopyTo(excludeCredentialsCopy, 0);
            ExcludeCredentials = excludeCredentialsCopy;
        }

        AuthenticatorSelection = authenticatorSelection;
        if (attestation.HasValue)
        {
            if (!Enum.IsDefined(typeof(AttestationConveyancePreference), attestation.Value))
            {
                throw new InvalidEnumArgumentException(nameof(attestation), (int) attestation.Value, typeof(AttestationConveyancePreference));
            }

            Attestation = attestation.Value;
        }

        Extensions = extensions;
    }

    /// <summary>
    ///     This member contains data about the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> responsible for the request.
    /// </summary>
    [Required]
    [JsonPropertyName("rp")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public PublicKeyCredentialRpEntity Rp { get; }

    /// <summary>
    ///     This member contains data about the user account for which the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> is requesting attestation.
    /// </summary>
    [Required]
    [JsonPropertyName("user")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public PublicKeyCredentialUserEntity User { get; }

    /// <summary>
    ///     This member contains a challenge intended to be used for generating the newly created credential’s <a href="https://www.w3.org/TR/webauthn-3/#attestation-object">attestation object</a>.
    /// </summary>
    [Required]
    [JsonPropertyName("challenge")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public byte[] Challenge { get; }

    /// <summary>
    ///     This member contains information about the desired properties of the credential to be created.
    ///     The sequence is ordered from most preferred to least preferred.
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> makes a best-effort to create the most preferred credential that it can.
    /// </summary>
    [Required]
    [JsonPropertyName("pubKeyCredParams")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public PublicKeyCredentialParameters[] PubKeyCredParams { get; }

    /// <summary>
    ///     This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
    ///     This is treated as a hint, and may be overridden by the <a href="https://www.w3.org/TR/webauthn-3/#client">client</a>.
    /// </summary>
    [JsonPropertyName("timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public uint? Timeout { get; }

    /// <summary>
    ///     This member is intended for use by <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a>
    ///     that wish to limit the creation of multiple credentials for the same account on a single authenticator.
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> is requested to return an error
    ///     if the new credential would be created on an authenticator that also contains one of the credentials enumerated in this parameter.
    /// </summary>
    [JsonPropertyName("excludeCredentials")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public PublicKeyCredentialDescriptor[]? ExcludeCredentials { get; }

    /// <summary>
    ///     This member is intended for use by <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a> that wish to select the appropriate authenticators
    ///     to participate in the <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-create">create()</a> operation.
    /// </summary>
    [JsonPropertyName("authenticatorSelection")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticatorSelectionCriteria? AuthenticatorSelection { get; }

    /// <summary>
    ///     This member is intended for use by <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a> that wish to
    ///     express their preference for <a href="https://www.w3.org/TR/webauthn-3/#attestation-conveyance">attestation conveyance</a>.
    ///     Its values should be members of <see cref="AttestationConveyancePreference" />. Client platforms must ignore unknown values,
    ///     treating an unknown value as if the member does not exist. Its default value is <see cref="AttestationConveyancePreference.None" />.
    /// </summary>
    [JsonPropertyName("attestation")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AttestationConveyancePreference? Attestation { get; }

    /// <summary>
    ///     This member contains additional parameters requesting additional processing by the client and authenticator.
    ///     For example, the caller may request that only authenticators with certain capabilities be used to create the credential,
    ///     or that particular information be returned in the <a href="https://www.w3.org/TR/webauthn-3/#attestation-object">attestation object</a>.
    /// </summary>
    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsClientInputs? Extensions { get; }
}
