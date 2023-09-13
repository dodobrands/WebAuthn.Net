using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text.Json.Serialization;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Models.Protocol.Request;

/// <summary>
///     This object contains the attributes that are specified by a caller when referring to a <a href="https://www.w3.org/TR/webauthn-2/#public-key-credential">public key credential</a> as an input parameter to the
///     <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-create">create()</a> or <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-get">get()</a> methods. It mirrors the fields of the PublicKeyCredential object returned
///     by the latter methods.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor">Web Authentication: An API for accessing Public Key Credentials Level 2 - § 5.8.3. Credential Descriptor</a>
/// </remarks>
public class PublicKeyCredentialDescriptor
{
    /// <summary>
    ///     Constructs <see cref="PublicKeyCredentialDescriptor" />.
    /// </summary>
    /// <param name="type">The type of the <a href="https://www.w3.org/TR/webauthn-2/#public-key-credential">public key credential</a> that the caller is referring to.</param>
    /// <param name="id">The <a href="https://www.w3.org/TR/webauthn-2/#credential-id">credential ID</a> of the <a href="https://www.w3.org/TR/webauthn-2/#public-key-credential">public key credential</a> that the caller is referring to.</param>
    /// <param name="transports">
    ///     A hint indicating how the <a href="https://www.w3.org/TR/webauthn-2/#client">client</a> could communicate with the <a href="https://www.w3.org/TR/webauthn-2/#public-key-credential-source-managing-authenticator">managing authenticator</a> of the public
    ///     key credential that the caller is referring to.
    /// </param>
    /// <exception cref="ArgumentException">If the parameter <paramref name="type" /> contains an invalid value or if the <paramref name="transports" /> array contains an invalid value.</exception>
    /// <exception cref="ArgumentNullException">If the parameter <paramref name="id" /> is equal to <see langword="null" />.</exception>
    [JsonConstructor]
    public PublicKeyCredentialDescriptor(
        PublicKeyCredentialType type,
        byte[] id,
        AuthenticatorTransport[]? transports)
    {
        if (!Enum.IsDefined(type))
        {
            throw new ArgumentException("Incorrect value", nameof(type));
        }

        Type = type;

        ArgumentNullException.ThrowIfNull(id);
        Id = id;

        if (transports?.Length > 0)
        {
            if (transports.Any(static x => !Enum.IsDefined(x)))
            {
                throw new ArgumentException($"One or more objects contained in the {nameof(transports)} enumeration contain an invalid value.", nameof(transports));
            }

            Transports = transports;
        }
    }

    /// <summary>
    ///     This member contains the type of the <a href="https://www.w3.org/TR/webauthn-2/#public-key-credential">public key credential</a> the caller is referring to.
    /// </summary>
    [JsonPropertyName("type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public PublicKeyCredentialType Type { get; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/webauthn-2/#credential-id">credential ID</a> of the <a href="https://www.w3.org/TR/webauthn-2/#public-key-credential">public key credential</a> that the caller is referring to.
    /// </summary>
    [JsonPropertyName("id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public byte[] Id { get; }

    /// <summary>
    ///     A hint indicating how the <a href="https://www.w3.org/TR/webauthn-2/#client">client</a> could communicate with the <a href="https://www.w3.org/TR/webauthn-2/#public-key-credential-source-managing-authenticator">managing authenticator</a> of the public key credential that the
    ///     caller is referring to.
    /// </summary>
    [JsonPropertyName("transports")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticatorTransport[]? Transports { get; }
}
