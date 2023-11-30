using System;

namespace WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;

/// <summary>
///     User Account Parameters for Credential Generation (dictionary PublicKeyCredentialUserEntity)
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-user-credential-params">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.4.3. User Account Parameters for Credential Generation (dictionary PublicKeyCredentialUserEntity)</a>
///     </para>
/// </remarks>
public class PublicKeyCredentialUserEntity
{
    /// <summary>
    ///     Constructs <see cref="PublicKeyCredentialUserEntity" />.
    /// </summary>
    /// <param name="name">
    ///     A <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#human-palatability">human-palatable</a> identifier for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account"> user account</a>. This identifier is the primary value displayed to users by
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">Clients</a> to help users understand with which <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> a credential is associated.
    /// </param>
    /// <param name="id">
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>. A
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> is an opaque <a href="https://infra.spec.whatwg.org/#byte-sequence">byte sequence</a> with a maximum size of 64 bytes, and is not meant to be displayed to the user.
    /// </param>
    /// <param name="displayName">
    ///     A <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#human-palatability">human-palatable</a> name for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>, intended only for display. The
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD let the user choose this, and SHOULD NOT restrict the choice more than necessary. If no suitable or
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#human-palatability">human-palatable</a> name is available, the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD set this value to an empty string.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="name" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="id" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException"><paramref name="id" /> must contain at least 1 byte</exception>
    /// <exception cref="ArgumentException"><paramref name="id" /> contains an array longer than 64 bytes</exception>
    /// <exception cref="ArgumentNullException"><paramref name="displayName" /> is <see langword="null" /></exception>
    public PublicKeyCredentialUserEntity(string name, byte[] id, string displayName)
    {
        // name
        ArgumentNullException.ThrowIfNull(name);
        Name = name;

        // id
        ArgumentNullException.ThrowIfNull(id);
        if (id.Length == 0)
        {
            throw new ArgumentException("The array must contain at least 1 byte", nameof(id));
        }

        if (id.Length > 64)
        {
            throw new ArgumentException("The array was longer than 64 bytes", nameof(id));
        }

        Id = id;

        // displayName
        ArgumentNullException.ThrowIfNull(displayName);
        DisplayName = displayName;
    }

    /// <summary>
    ///     A <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#human-palatability">human-palatable</a> identifier for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account"> user account</a>. This identifier is the primary value displayed to users by
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">Clients</a> to help users understand with which <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> a credential is associated.
    /// </summary>
    /// <remarks>
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
    public string Name { get; }

    /// <summary>
    ///     <para>
    ///         The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>. A
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> is an opaque <a href="https://infra.spec.whatwg.org/#byte-sequence">byte sequence</a> with a maximum size of 64 bytes, and is not meant to be displayed to the user.
    ///     </para>
    ///     <para>
    ///         To ensure secure operation, authentication and authorization decisions MUST be made on the basis of this <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-id">id</a> member, not the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-displayname">displayName</a> nor <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialentity-name">name</a> members. See Section 6.1 of
    ///         <a href="https://www.rfc-editor.org/rfc/rfc8266.html#section-6.1">RFC 8266</a>.
    ///     </para>
    ///     <para>
    ///         The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> MUST NOT contain personally identifying information about the user, such as a username or e-mail address; see
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-user-handle-privacy">§14.6.1 User Handle Contents</a> for details. The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> MUST NOT be empty.
    ///     </para>
    /// </summary>
    /// <remarks>
    ///     The user handle ought not be a constant value across different user accounts, even for non-discoverable credentials, because some authenticators always create discoverable credentials. Thus a constant user handle would prevent a user from using such an authenticator with
    ///     more than one user account at the Relying Party.
    /// </remarks>
    public byte[] Id { get; }

    /// <summary>
    ///     A <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#human-palatability">human-palatable</a> name for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>, intended only for display. The
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD let the user choose this, and SHOULD NOT restrict the choice more than necessary. If no suitable or
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#human-palatability">human-palatable</a> name is available, the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD set this value to an empty string.
    /// </summary>
    /// <remarks>
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
    public string DisplayName { get; }
}
