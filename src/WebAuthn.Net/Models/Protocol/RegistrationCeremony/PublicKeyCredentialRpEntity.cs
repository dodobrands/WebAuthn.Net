using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Models.Protocol.RegistrationCeremony;

/// <summary>
///     Relying Party Parameters for Credential Generation
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-rp-credential-params">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.4.2. Relying Party Parameters for Credential Generation</a>
/// </remarks>
public class PublicKeyCredentialRpEntity
{
    /// <summary>
    ///     Constructs <see cref="PublicKeyCredentialRpEntity" />.
    /// </summary>
    /// <param name="name">A <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#human-palatability">human-palatable</a> identifier for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>, intended only for display.</param>
    /// <param name="id">A unique identifier for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> entity, which sets the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#rp-id">RP ID</a>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="name" /> is <see langword="null" /></exception>
    [JsonConstructor]
    public PublicKeyCredentialRpEntity(string name, string? id)
    {
        ArgumentNullException.ThrowIfNull(name);
        Name = name;
        Id = id;
    }

    /// <summary>
    ///     A <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#human-palatability">human-palatable</a> identifier for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>, intended only for display.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         For example:
    ///         <list type="bullet">
    ///             <item>
    ///                 <description>ACME Corporation</description>
    ///             </item>
    ///             <item>
    ///                 <description>Wonderful Widgets, Inc.</description>
    ///             </item>
    ///             <item>
    ///                 <description>ОАО Примертех</description>
    ///             </item>
    ///         </list>
    ///     </para>
    ///     <para>Authenticators MAY truncate a name member’s value so that it fits within 64 bytes, if the authenticator stores the value.</para>
    /// </remarks>
    [JsonPropertyName("name")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Name { get; }

    /// <summary>
    ///     A unique identifier for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> entity, which sets the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#rp-id">RP ID</a>.
    /// </summary>
    /// <remarks>
    ///     Specifies the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#rp-id">RP ID</a> the credential should be <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#scope">scoped</a> to. If omitted, its value will be the
    ///     <a href="https://w3c.github.io/webappsec-credential-management/#credentialscontainer">CredentialsContainer</a> object’s <a href="https://html.spec.whatwg.org/multipage/webappapis.html#relevant-settings-object">relevant settings object's</a>
    ///     <a href="https://html.spec.whatwg.org/multipage/webappapis.html#concept-settings-object-origin">origin's</a> <a href="https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-effective-domain">effective domain</a>.
    /// </remarks>
    [JsonPropertyName("id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Id { get; }
}
