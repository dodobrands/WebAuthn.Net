using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text.Json.Serialization;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Models.Protocol.Request;

/// <summary>
///     Options for credential creation.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrequestoptions">Web Authentication: An API for accessing Public Key Credentials Level 2 - § 5.5. Options for Assertion Generation</a>
/// </remarks>
public class PublicKeyCredentialRequestOptions
{
    /// <summary>
    ///     Constructs <see cref="PublicKeyCredentialRequestOptions" />.
    /// </summary>
    /// <param name="challenge">
    ///     Represents a challenge that the selected <a href="https://www.w3.org/TR/webauthn-2/#authenticator">authenticator</a> signs, along with other data, when producing an
    ///     <a href="https://www.w3.org/TR/webauthn-2/#authentication-assertion">authentication assertion</a>.
    /// </param>
    /// <param name="timeout">A numerical hint, in milliseconds, indicating the time the relying party (web application backend) is willing to wait for the retrieval operation to complete. This hint may be overridden by the browser.</param>
    /// <param name="rpId">A string that specifies the relying party's identifier (for example "login.example.org").</param>
    /// <param name="allowCredentials">A collection of objects that define a restricted list of acceptable credentials for retrieval.</param>
    /// <param name="userVerification">Sets the requirements of the relying party for user verification during the authentication process.</param>
    /// <param name="extensions">Contains additional parameters requesting additional processing by the client and authenticator.</param>
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
    ///     Represents a challenge that the selected <a href="https://www.w3.org/TR/webauthn-2/#authenticator">authenticator</a> signs, along with other data, when producing an <a href="https://www.w3.org/TR/webauthn-2/#authentication-assertion">authentication assertion</a>. This value
    ///     will be signed by the authenticator and the signature will be sent back as part of the AuthenticatorAssertionResponse.signature (available in the response property of the PublicKeyCredential object returned by a successful get() call).
    /// </summary>
    [JsonPropertyName("challenge")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public byte[] Challenge { get; }

    /// <summary>
    ///     A numerical hint, in milliseconds, indicating the time the relying party (web application backend) is willing to wait for the retrieval operation to complete. This hint may be overridden by the browser.
    /// </summary>
    [JsonPropertyName("timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public uint? Timeout { get; }

    /// <summary>
    ///     A string that specifies the relying party's identifier (for example "login.example.org").
    ///     For security purposes:
    ///     <list type="bullet">
    ///         <item>
    ///             <description>
    ///                 The calling web app verifies that <see cref="RpId" /> matches the relying party's origin.
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <description>
    ///                 The authenticator verifies that <see cref="RpId" /> matches the rpId of the credential used for the authentication ceremony.
    ///             </description>
    ///         </item>
    ///     </list>
    ///     If omitted, its value will be the <a href="https://www.w3.org/TR/credential-management-1/#credentialscontainer">CredentialsContainer</a> object’s <a href="https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object">relevant settings</a> object's
    ///     <a href="https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin">origin's</a> <a href="https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-effective-domain">effective domain</a> (to the current origin's domain).
    /// </summary>
    [JsonPropertyName("rpId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RpId { get; }

    /// <summary>
    ///     A collection of objects that define a restricted list of acceptable credentials for retrieval.
    /// </summary>
    [JsonPropertyName("allowCredentials")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public PublicKeyCredentialDescriptor[]? AllowCredentials { get; }

    /// <summary>
    ///     Sets the requirements of the relying party for user verification during the authentication process. Describes the <a href="https://www.w3.org/TR/webauthn-2/#relying-party">relying party's</a> requirements for
    ///     <a href="https://www.w3.org/TR/webauthn-2/#user-verification">user verification</a> during the <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-get">get()</a> operation. The value should be a member of
    ///     <see cref="UserVerificationRequirement" /> but client platforms must ignore unknown values, treating an unknown value as if the member does not exist. Eligible authenticators are filtered to only those capable of satisfying this requirement.
    /// </summary>
    [JsonPropertyName("userVerification")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public UserVerificationRequirement? UserVerification { get; }

    /// <summary>
    ///     Contains additional parameters requesting additional processing by the client and authenticator. For example, if transaction confirmation is sought from the user, then the prompt string might be included as an extension.
    /// </summary>
    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsClientInputs? Extensions { get; }
}
