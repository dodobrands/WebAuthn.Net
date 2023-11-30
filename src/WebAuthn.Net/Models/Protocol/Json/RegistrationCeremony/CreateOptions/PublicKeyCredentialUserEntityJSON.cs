using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateOptions;

/// <summary>
///     User Account Parameters for Credential Generation (dictionary PublicKeyCredentialUserEntity)
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-user-credential-params">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.4.3. User Account Parameters for Credential Generation (dictionary PublicKeyCredentialUserEntity)</a>
///     </para>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-parseCreationOptionsFromJSON">
///             Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.1.9. Deserialize Registration ceremony options - PublicKeyCredential's
///             parseCreationOptionsFromJSON() Method
///         </a>
///     </para>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictdef-publickeycredentialcreationoptions">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.4. Options for Credential Creation (dictionary PublicKeyCredentialCreationOptions)</a>
///     </para>
/// </remarks>
// ReSharper disable once InconsistentNaming
public class PublicKeyCredentialUserEntityJSON
{
    /// <summary>
    ///     Constructs <see cref="PublicKeyCredentialUserEntityJSON" />.
    /// </summary>
    /// <param name="id">
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>. A
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> is an opaque <a href="https://infra.spec.whatwg.org/#byte-sequence">byte sequence</a> with a maximum size of 64 bytes, and is not meant to be displayed to the user.
    /// </param>
    /// <param name="name">
    ///     A <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#human-palatability">human-palatable</a> identifier for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account"> user account</a>. This identifier is the primary value displayed
    ///     to users by <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">Clients</a> to help users understand with which <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> a credential is associated.
    /// </param>
    /// <param name="displayName">
    ///     A <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#human-palatability">human-palatable</a> name for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>, intended only for display. The
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD let the user choose this, and SHOULD NOT restrict the choice more than necessary. If no suitable or
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#human-palatability">human-palatable</a> name is available, the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD set this value to an empty string.
    /// </param>
    [JsonConstructor]
    public PublicKeyCredentialUserEntityJSON(string id, string name, string displayName)
    {
        Id = id;
        Name = name;
        DisplayName = displayName;
    }

    /// <summary>
    ///     <para>
    ///         The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>. A
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> is an opaque <a href="https://infra.spec.whatwg.org/#byte-sequence">byte sequence</a> with a maximum size of 64 bytes, and is not meant to be displayed to the user.
    ///     </para>
    ///     <para>
    ///         To ensure secure operation, authentication and authorization decisions MUST be made on the basis of this <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-id">id</a> member, not the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-displayname">displayName</a> nor <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialentity-name">name</a> members. See
    ///         <a href="https://www.rfc-editor.org/rfc/rfc8266.html#section-6.1">Section 6.1 of RFC 8266</a>.
    ///     </para>
    ///     <para>
    ///         The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> MUST NOT contain personally identifying information about the user, such as a username or e-mail address; see
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-user-handle-privacy">§14.6.1 User Handle Contents</a> for details. The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> MUST NOT be empty.
    ///     </para>
    /// </summary>
    /// <remarks>
    ///     <para>Base64URLString</para>
    ///     <para>
    ///         The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> ought not be a constant value across different <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user accounts</a>, even for
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#non-discoverable-credential">non-discoverable credentials</a>, because some authenticators always create
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credentials</a>. Thus a constant <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> would prevent a user from using such an
    ///         authenticator with more than one <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> at the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>.
    ///     </para>
    /// </remarks>
    [JsonPropertyName("id")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Id { get; }

    /// <summary>
    ///     A <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#human-palatability">human-palatable</a> identifier for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account"> user account</a>. This identifier is the primary value displayed to users by
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">Clients</a> to help users understand with which <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> a credential is associated.
    /// </summary>
    /// <remarks>
    ///     <para>DOMString</para>
    ///     <para>
    ///         Examples of suitable values for this identifier include:
    ///         <list type="bullet">
    ///             <item>
    ///                 <description>alexm</description>
    ///             </item>
    ///             <item>
    ///                 <description>+14255551234</description>
    ///             </item>
    ///             <item>
    ///                 <description>alex.mueller@example.com</description>
    ///             </item>
    ///             <item>
    ///                 <description>alex.mueller@example.com (prod-env)</description>
    ///             </item>
    ///             <item>
    ///                 <description>alex.mueller@example.com (ОАО Примертех)</description>
    ///             </item>
    ///         </list>
    ///     </para>
    ///     <para>The Relying Party MAY let the user choose this value.</para>
    ///     <para>Authenticators MAY truncate a name member's value so that it fits within 64 bytes, if the authenticator stores the value.</para>
    /// </remarks>
    [JsonPropertyName("name")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Name { get; }

    /// <summary>
    ///     A <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#human-palatability">human-palatable</a> name for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>, intended only for display. The
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD let the user choose this, and SHOULD NOT restrict the choice more than necessary. If no suitable or
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#human-palatability">human-palatable</a> name is available, the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD set this value to an empty string.
    /// </summary>
    /// <remarks>
    ///     <para>DOMString</para>
    ///     <para>
    ///         Examples of suitable values for this identifier include:
    ///         <list type="bullet">
    ///             <item>
    ///                 <description>Alex Müller</description>
    ///             </item>
    ///             <item>
    ///                 <description>Alex Müller (ACME Co.)</description>
    ///             </item>
    ///             <item>
    ///                 <description>田中倫</description>
    ///             </item>
    ///         </list>
    ///     </para>
    ///     <para>Authenticators MUST accept and store a 64-byte minimum length for a displayName member's value.</para>
    ///     <para>Authenticators MAY truncate a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-displayname">displayName</a> member's value so that it fits within 64 bytes.</para>
    /// </remarks>
    [JsonPropertyName("displayName")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string DisplayName { get; }
}
