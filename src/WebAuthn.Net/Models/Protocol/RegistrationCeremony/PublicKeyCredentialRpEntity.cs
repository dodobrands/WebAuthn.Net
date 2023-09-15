using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Models.Protocol.RegistrationCeremony;

/// <summary>
///     Relying Party Parameters for Credential Generation
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#dictionary-rp-credential-params">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.4.2. Relying Party Parameters for Credential Generation</a>
/// </remarks>
public class PublicKeyCredentialRpEntity
{
    /// <summary>
    ///     Constructs <see cref="PublicKeyCredentialRpEntity" />.
    /// </summary>
    /// <param name="id">
    ///     This member specifies the <a href="https://www.w3.org/TR/webauthn-3/#rp-id">RP ID</a> the credential should be <a href="https://www.w3.org/TR/webauthn-3/#scope">scoped</a> to.
    ///     If omitted, its value will be the <a href="https://www.w3.org/TR/credential-management-1/#credentialscontainer">CredentialsContainer</a> object’s
    ///     <a href="https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object">relevant settings object's</a>
    ///     <a href="https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin">origin's</a>
    ///     <a href="https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-effective-domain">effective domain</a>.
    /// </param>
    /// <param name="name">
    ///     A <a href="https://www.w3.org/TR/webauthn-3/#human-palatability">human-palatable</a> identifier for the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a>,
    ///     intended only for display. For example, "ACME Corporation", "Wonderful Widgets, Inc." or "ОАО Примертех".
    /// </param>
    /// <exception cref="ArgumentException">If the parameter <paramref name="name" /> contains an empty string or <see langword="null" /> value.</exception>
    [JsonConstructor]
    public PublicKeyCredentialRpEntity(string? id, string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(name));
        }

        Id = id;
        Name = name;
    }

    /// <summary>
    ///     This member specifies the <a href="https://www.w3.org/TR/webauthn-3/#rp-id">RP ID</a> the credential should be <a href="https://www.w3.org/TR/webauthn-3/#scope">scoped</a> to.
    ///     If omitted, its value will be the <a href="https://www.w3.org/TR/credential-management-1/#credentialscontainer">CredentialsContainer</a> object’s
    ///     <a href="https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object">relevant settings object's</a>
    ///     <a href="https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin">origin's</a>
    ///     <a href="https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-effective-domain">effective domain</a>.
    /// </summary>
    [JsonPropertyName("id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Id { get; }

    /// <summary>
    ///     A <a href="https://www.w3.org/TR/webauthn-3/#human-palatability">human-palatable</a> identifier
    ///     for the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a>,
    ///     intended only for display.
    ///     For example, "ACME Corporation", "Wonderful Widgets, Inc." or "ОАО Примертех".
    /// </summary>
    [JsonPropertyName("name")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Name { get; }
}
