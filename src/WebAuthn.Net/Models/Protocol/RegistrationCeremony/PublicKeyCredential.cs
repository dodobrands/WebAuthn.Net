using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Serialization.Json;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Models.Protocol.RegistrationCeremony;

/// <summary>
///     An object that contains the attributes that are returned to the caller when a new credential is created.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#iface-pkcredential">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.1. PublicKeyCredential</a>
/// </remarks>
public class PublicKeyCredential
{
    /// <summary>
    ///     Constructs <see cref="PublicKeyCredential" />.
    /// </summary>
    /// <param name="id">
    ///     This attribute is inherited from <a href="https://www.w3.org/TR/credential-management-1/#credential">Credential</a>,
    ///     though <a href="https://www.w3.org/TR/webauthn-3/#publickeycredential">PublicKeyCredential</a>
    ///     overrides <a href="https://www.w3.org/TR/credential-management-1/#credential">Credential's</a> getter,
    ///     instead returning the <a href="https://www.w3.org/TR/webauthn-3/#base64url-encoding">base64url</a> encoding of the data contained in the object’s
    ///     <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-identifier-slot">[[identifier]]</a>
    ///     <a href="https://tc39.es/ecma262/#sec-object-internal-methods-and-internal-slots">internal slot</a>.
    /// </param>
    /// <param name="type">
    ///     The value of the object’s <a href="https://webidl.spec.whatwg.org/#dfn-interface-object">interface object's</a> <a href="https://www.w3.org/TR/credential-management-1/#dom-credential-type-slot">[[type]]</a> slot,
    ///     which specifies the credential type represented by this object.
    /// </param>
    /// <param name="rawId">
    ///     This attribute returns the <a href="https://webidl.spec.whatwg.org/#idl-ArrayBuffer">ArrayBuffer</a>
    ///     contained in the <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-identifier-slot">[[identifier]]</a> internal slot.
    /// </param>
    /// <param name="response">
    ///     This attribute contains the <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator's</a> response to the client’s request to create
    ///     a <a href="https://www.w3.org/TR/webauthn-3/#public-key-credential">public key credential</a>.
    /// </param>
    /// <exception cref="InvalidEnumArgumentException">If the <paramref name="type" /> parameter contains a value not defined in the <see cref="PublicKeyCredentialType" /> enum.</exception>
    /// <exception cref="ArgumentNullException">If the <paramref name="id" />, <paramref name="rawId" />, or <paramref name="response" /> parameters are <see langword="null" />.</exception>
    /// <exception cref="ArgumentException">If the <paramref name="id" /> parameter contains surrogate pairs.</exception>
    [JsonConstructor]
    public PublicKeyCredential(string id, PublicKeyCredentialType type, byte[] rawId, AuthenticatorAttestationResponse response)
    {
        ArgumentNullException.ThrowIfNull(id, nameof(id));
        if (!UsvStringValidator.IsValid(id))
        {
            throw new ArgumentException($"{nameof(id)} must be a string that doesn't contain surrogate pairs.", nameof(id));
        }

        if (!Enum.IsDefined(typeof(PublicKeyCredentialType), type))
        {
            throw new InvalidEnumArgumentException(nameof(type), (int) type, typeof(PublicKeyCredentialType));
        }

        ArgumentNullException.ThrowIfNull(rawId, nameof(rawId));
        ArgumentNullException.ThrowIfNull(response, nameof(response));

        Id = id;
        Type = type;
        RawId = rawId;
        Response = response;
    }

    /// <summary>
    ///     This attribute is inherited from <a href="https://www.w3.org/TR/credential-management-1/#credential">Credential</a>,
    ///     though <a href="https://www.w3.org/TR/webauthn-3/#publickeycredential">PublicKeyCredential</a>
    ///     overrides <a href="https://www.w3.org/TR/credential-management-1/#credential">Credential's</a> getter,
    ///     instead returning the <a href="https://www.w3.org/TR/webauthn-3/#base64url-encoding">base64url</a> encoding of the data contained in the object’s
    ///     <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-identifier-slot">[[identifier]]</a>
    ///     <a href="https://tc39.es/ecma262/#sec-object-internal-methods-and-internal-slots">internal slot</a>.
    /// </summary>
    [JsonPropertyName("id")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Id { get; }

    /// <summary>
    ///     The value of the object’s <a href="https://webidl.spec.whatwg.org/#dfn-interface-object">interface object's</a> <a href="https://www.w3.org/TR/credential-management-1/#dom-credential-type-slot">[[type]]</a> slot,
    ///     which specifies the credential type represented by this object.
    /// </summary>
    [JsonPropertyName("type")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public PublicKeyCredentialType Type { get; }

    /// <summary>
    ///     This attribute returns the <a href="https://webidl.spec.whatwg.org/#idl-ArrayBuffer">ArrayBuffer</a>
    ///     contained in the <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-identifier-slot">[[identifier]]</a> internal slot.
    /// </summary>
    [JsonPropertyName("rawId")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[] RawId { get; }

    /// <summary>
    ///     This attribute contains the <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator's</a> response to the client’s request to create
    ///     a <a href="https://www.w3.org/TR/webauthn-3/#public-key-credential">public key credential</a>.
    /// </summary>
    [JsonPropertyName("response")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public AuthenticatorAttestationResponse Response { get; }
}
