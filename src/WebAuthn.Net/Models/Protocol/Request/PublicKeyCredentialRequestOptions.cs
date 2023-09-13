using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text.Json.Serialization;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Models.Protocol.Request;

/// <summary>
///     Options for assertion generation.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#dictionary-assertion-options">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.5. Options for Assertion Generation</a>
/// </remarks>
public class PublicKeyCredentialRequestOptions
{
    /// <summary>
    ///     Constructs <see cref="PublicKeyCredentialRequestOptions" />.
    /// </summary>
    /// <param name="challenge">
    ///     This member represents a challenge that the selected <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> signs,
    ///     along with other data, when producing an <a href="https://www.w3.org/TR/webauthn-3/#authentication-assertion">authentication assertion</a>.
    /// </param>
    /// <param name="timeout">
    ///     This optional member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
    ///     The value is treated as a hint, and MAY be overridden by the <a href="https://www.w3.org/TR/webauthn-3/#client">client</a>.
    /// </param>
    /// <param name="rpId">
    ///     This optional member specifies the <a href="https://www.w3.org/TR/webauthn-3/#relying-party-identifier">relying party identifier</a> claimed by the caller.
    ///     If omitted, its value will be the <a href="https://www.w3.org/TR/credential-management-1/#credentialscontainer">CredentialsContainer</a> object’s
    ///     <a href="https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object">relevant settings object's</a>
    ///     <a href="https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin">origin's</a>
    ///     <a href="https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-effective-domain">effective domain</a>.
    /// </param>
    /// <param name="allowCredentials">
    ///     This optional member contains a list of <see cref="PublicKeyCredentialDescriptor" /> objects
    ///     representing <a href="https://www.w3.org/TR/webauthn-3/#public-key-credential">public key credentials</a> acceptable to the caller,
    ///     in descending order of the caller’s preference (the first item in the list is the most preferred credential, and so on down the list).
    /// </param>
    /// <param name="userVerification">
    ///     This optional member describes the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party's</a> requirements regarding
    ///     <a href="https://www.w3.org/TR/webauthn-3/#user-verification">user verification</a> for the <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-get">get()</a> operation.
    ///     The value should be a member of <see cref="UserVerificationRequirement" /> but <a href="https://www.w3.org/TR/webauthn-3/#client-platform">client platforms</a> must ignore unknown values,
    ///     treating an unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    ///     Eligible authenticators are filtered to only those capable of satisfying this requirement.
    /// </param>
    /// <param name="extensions">This optional member contains additional parameters requesting additional processing by the client and authenticator. For example, if transaction confirmation is sought from the user, then the prompt string might be included as an extension.</param>
    /// <exception cref="ArgumentNullException">If the parameter <paramref name="challenge" /> is equal to <see langword="null" />.</exception>
    /// <exception cref="ArgumentException">If the <paramref name="rpId" /> parameter contains surrogate pairs, or the <paramref name="allowCredentials" /> array contains a <see langword="null" /> object, or the <paramref name="userVerification" /> parameter contains an invalid value.</exception>
    [JsonConstructor]
    public PublicKeyCredentialRequestOptions(
        byte[] challenge,
        uint? timeout,
        string? rpId,
        PublicKeyCredentialDescriptor[]? allowCredentials,
        UserVerificationRequirement? userVerification,
        AuthenticationExtensionsClientInputs? extensions)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        var challengeCopy = new byte[challenge.Length];
        challenge.CopyTo(challengeCopy, 0);
        Challenge = challengeCopy;
        Timeout = timeout;
        if (rpId is not null)
        {
            if (!USVStringValidator.IsValid(rpId))
            {
                throw new ArgumentException($"{nameof(rpId)} must be a string that doesn't contain surrogate pairs.", nameof(rpId));
            }

            RpId = rpId;
        }

        if (allowCredentials?.Length > 0)
        {
            // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
            if (allowCredentials.Any(static x => x is null))
            {
                throw new ArgumentException($"One or more objects contained in the {nameof(allowCredentials)} enumeration are equal to null.", nameof(allowCredentials));
            }

            var allowCredentialsCopy = new PublicKeyCredentialDescriptor[allowCredentials.Length];
            allowCredentials.CopyTo(allowCredentialsCopy, 0);
            AllowCredentials = allowCredentialsCopy;
        }

        if (userVerification.HasValue)
        {
            if (!Enum.IsDefined(userVerification.Value))
            {
                throw new ArgumentException("Incorrect value", nameof(userVerification));
            }

            UserVerification = userVerification.Value;
        }

        Extensions = extensions;
    }

    /// <summary>
    ///     This member represents a challenge that the selected <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> signs,
    ///     along with other data, when producing an <a href="https://www.w3.org/TR/webauthn-3/#authentication-assertion">authentication assertion</a>.
    /// </summary>
    [JsonPropertyName("challenge")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public byte[] Challenge { get; }

    /// <summary>
    ///     This optional member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
    ///     The value is treated as a hint, and MAY be overridden by the <a href="https://www.w3.org/TR/webauthn-3/#client">client</a>.
    /// </summary>
    [JsonPropertyName("timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public uint? Timeout { get; }

    /// <summary>
    ///     This optional member specifies the <a href="https://www.w3.org/TR/webauthn-3/#relying-party-identifier">relying party identifier</a> claimed by the caller.
    ///     If omitted, its value will be the <a href="https://www.w3.org/TR/credential-management-1/#credentialscontainer">CredentialsContainer</a> object’s
    ///     <a href="https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object">relevant settings object's</a>
    ///     <a href="https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin">origin's</a>
    ///     <a href="https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-effective-domain">effective domain</a>.
    /// </summary>
    [JsonPropertyName("rpId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RpId { get; }

    /// <summary>
    ///     This optional member contains a list of <see cref="PublicKeyCredentialDescriptor" /> objects
    ///     representing <a href="https://www.w3.org/TR/webauthn-3/#public-key-credential">public key credentials</a> acceptable to the caller,
    ///     in descending order of the caller’s preference (the first item in the list is the most preferred credential, and so on down the list).
    /// </summary>
    [JsonPropertyName("allowCredentials")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public PublicKeyCredentialDescriptor[]? AllowCredentials { get; }

    /// <summary>
    ///     This optional member describes the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party's</a> requirements regarding
    ///     <a href="https://www.w3.org/TR/webauthn-3/#user-verification">user verification</a> for the <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-get">get()</a> operation.
    ///     The value should be a member of <see cref="UserVerificationRequirement" /> but <a href="https://www.w3.org/TR/webauthn-3/#client-platform">client platforms</a> must ignore unknown values,
    ///     treating an unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    ///     Eligible authenticators are filtered to only those capable of satisfying this requirement.
    /// </summary>
    [JsonPropertyName("userVerification")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public UserVerificationRequirement? UserVerification { get; }

    /// <summary>
    ///     This optional member contains additional parameters requesting additional processing by the client and authenticator. For example, if transaction confirmation is sought from the user, then the prompt string might be included as an extension.
    /// </summary>
    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsClientInputs? Extensions { get; }
}
