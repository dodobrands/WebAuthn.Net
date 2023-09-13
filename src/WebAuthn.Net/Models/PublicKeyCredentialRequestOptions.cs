using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using WebAuthn.Net.Models.Enums;

namespace WebAuthn.Net.Models;

/// <summary>
///     Options for credential creation.
///     <br />
///     <a href="https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrequestoptions">Web Authentication: An API for accessing Public Key Credentials Level 2. § 5.5. Options for Assertion Generation</a> (dictionary <see cref="PublicKeyCredentialRequestOptions" />)
/// </summary>
public class PublicKeyCredentialRequestOptions
{
    [JsonConstructor]
    public PublicKeyCredentialRequestOptions(
        byte[] challenge,
        uint? timeout,
        string? rpId,
        IReadOnlyCollection<PublicKeyCredentialDescriptor>? allowCredentials,
        UserVerificationRequirement userVerification,
        AuthenticationExtensionsClientInputs? extensions)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        Challenge = challenge;
        Timeout = timeout;
        RpId = rpId;
        AllowCredentials = allowCredentials;
        UserVerification = userVerification;
        Extensions = extensions;
    }

    /// <summary>
    ///     Represents a challenge that the selected <a href="https://www.w3.org/TR/webauthn-2/#authenticator">authenticator</a> signs, along with other data, when producing an <a href="https://www.w3.org/TR/webauthn-2/#authentication-assertion">authentication assertion</a>. This value will be signed by the authenticator and the signature will be sent back as part of the AuthenticatorAssertionResponse.signature (available in the response property of the PublicKeyCredential object returned by a successful get() call).
    /// </summary>
    [JsonPropertyName("challenge")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public byte[] Challenge { get; }

    /// <summary>
    /// A numerical hint, in milliseconds, indicating the time the relying party (web application backend) is willing to wait for the retrieval operation to complete. This hint may be overridden by the browser.
    /// </summary>
    [JsonPropertyName("timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public uint? Timeout { get; }

    /// <summary>
    /// A string that specifies the relying party's identifier (for example "login.example.org").
    /// For security purposes:
    ///     <list type="bullet">
    ///         <item>
    ///             <description>
    ///                 The calling web app verifies that <see cref="RpId"/> matches the relying party's origin.
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <description>
    ///                 The authenticator verifies that <see cref="RpId"/> matches the rpId of the credential used for the authentication ceremony.
    ///             </description>
    ///         </item>
    ///     </list>
    /// If omitted, its value will be the <a href="https://www.w3.org/TR/credential-management-1/#credentialscontainer">CredentialsContainer</a> object’s <a href="https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object">relevant settings</a> object's <a href="https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin">origin's</a> <a href="https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-effective-domain">effective domain</a> (to the current origin's domain).
    /// </summary>
    [JsonPropertyName("rpId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RpId { get; }

    /// <summary>
    ///
    /// </summary>
    [JsonPropertyName("allowCredentials")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyCollection<PublicKeyCredentialDescriptor>? AllowCredentials { get; }

    [JsonPropertyName("userVerification")]
    public UserVerificationRequirement UserVerification { get; }

    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticationExtensionsClientInputs? Extensions { get; }
}
