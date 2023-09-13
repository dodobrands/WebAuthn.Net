using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Models.Protocol.Creation;

/// <summary>
///     User Account Parameters for Credential Generation
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#dictionary-user-credential-params">Web Authentication: An API for accessing Public Key Credentials Level 3 - § 5.4.3. User Account Parameters for Credential Generation</a>
/// </remarks>
public class PublicKeyCredentialUserEntity
{
    /// <summary>
    ///     Constructs <see cref="PublicKeyCredentialUserEntity" />.
    /// </summary>
    /// <param name="id">
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> of the user account entity.
    ///     A <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> is an opaque <a href="https://infra.spec.whatwg.org/#byte-sequence">byte sequence</a>
    ///     with a maximum size of 64 bytes, and is not meant to be displayed to the user.
    ///     To ensure secure operation, authentication and authorization decisions must be made on the basis of this <see cref="Id" /> member,
    ///     not the <see cref="DisplayName" /> nor <see cref="Name" /> members.
    /// </param>
    /// <param name="displayName">
    ///     A <a href="https://www.w3.org/TR/webauthn-3/#human-palatability">human-palatable</a> name for the user account, intended only for display.
    ///     For example, "Alex Müller" or "田中倫".
    ///     The <a href="Relying Party">Relying Party</a> should let the user choose this, and should not restrict the choice more than necessary.
    /// </param>
    /// <param name="name">
    ///     A <a href="https://www.w3.org/TR/webauthn-3/#human-palatability">human-palatable</a> identifier for a user account.
    ///     It is intended only for display, i.e., aiding the user in determining the difference between user accounts
    ///     with similar <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-displayname">displayNames</a>.
    ///     For example, "alexm", "alex.mueller@example.com" or "+14255551234".
    /// </param>
    /// <exception cref="ArgumentNullException">If the parameter <paramref name="id" /> is equal to <see langword="null" />.</exception>
    /// <exception cref="ArgumentException">
    ///     If the <paramref name="id" /> parameter contains an empty sequence or if the <paramref name="id" /> parameter contains a sequence longer than 64 bytes,
    ///     or if the <paramref name="displayName" /> or <paramref name="name" /> parameters equal to empty string or <see langword="null" />.
    /// </exception>
    public PublicKeyCredentialUserEntity(byte[] id, string displayName, string name)
    {
        ArgumentNullException.ThrowIfNull(id);
        switch (id.Length)
        {
            case 0:
                throw new ArgumentException("Value cannot be an empty collection.", nameof(id));
            case > 64:
                throw new ArgumentException("The value should not contain a sequence of more than 64 bytes.", nameof(id));
        }

        if (string.IsNullOrEmpty(displayName))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(displayName));
        }

        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(name));
        }

        var idCopy = new byte[id.Length];
        id.CopyTo(idCopy, 0);
        Id = idCopy;
        DisplayName = displayName;
        Name = name;
    }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> of the user account entity.
    ///     A <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> is an opaque <a href="https://infra.spec.whatwg.org/#byte-sequence">byte sequence</a>
    ///     with a maximum size of 64 bytes, and is not meant to be displayed to the user.
    ///     To ensure secure operation, authentication and authorization decisions must be made on the basis of this <see cref="Id" /> member,
    ///     not the <see cref="DisplayName" /> nor <see cref="Name" /> members.
    /// </summary>
    [JsonPropertyName("id")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public byte[] Id { get; }

    /// <summary>
    ///     A <a href="https://www.w3.org/TR/webauthn-3/#human-palatability">human-palatable</a> name for the user account, intended only for display.
    ///     For example, "Alex Müller" or "田中倫".
    ///     The <a href="Relying Party">Relying Party</a> should let the user choose this, and should not restrict the choice more than necessary.
    /// </summary>
    [JsonPropertyName("displayName")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string DisplayName { get; }

    /// <summary>
    ///     A <a href="https://www.w3.org/TR/webauthn-3/#human-palatability">human-palatable</a> identifier for a user account.
    ///     It is intended only for display, i.e., aiding the user in determining the difference between user accounts
    ///     with similar <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-displayname">displayNames</a>.
    ///     For example, "alexm", "alex.mueller@example.com" or "+14255551234".
    /// </summary>
    [JsonPropertyName("name")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Name { get; }
}
