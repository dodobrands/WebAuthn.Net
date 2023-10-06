using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Serialization.Json;

namespace WebAuthn.Net.Models.Protocol;

/// <summary>
///     This dictionary identifies a specific <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">public key credential</a>. It is used in <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create">create()</a> to
///     prevent creating duplicate credentials on the same <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>, and in <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get">get()</a> to determine if and
///     how the credential can currently be reached by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a>. It mirrors some fields of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#publickeycredential">PublicKeyCredential</a> object
///     returned by <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create">create()</a> and <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get">get()</a>.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-credential-descriptor">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.8.3. Credential Descriptor</a>
/// </remarks>
public class PublicKeyCredentialDescriptor
{
    /// <summary>
    ///     Constructs <see cref="PublicKeyCredentialDescriptor" />.
    /// </summary>
    /// <param name="type">
    ///     <para>
    ///         This member contains the type of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">public key credential</a> the caller is referring to. The value SHOULD be a member of
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialtype">PublicKeyCredentialType</a> but <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore any
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictdef-publickeycredentialdescriptor">PublicKeyCredentialDescriptor</a> with an unknown <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialdescriptor-type">type</a>.
    ///     </para>
    ///     <para>This mirrors the <a href="https://www.w3.org/TR/credential-management-1/#dom-credential-type">type</a> field of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#publickeycredential">PublicKeyCredential</a>.</para>
    /// </param>
    /// <param name="id">
    ///     <para>This member contains the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id">credential ID</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">public key credential</a> the caller is referring to.</para>
    ///     <para>This mirrors the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredential-rawid">rawId</a> field of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#publickeycredential">PublicKeyCredential</a>.</para>
    /// </param>
    /// <param name="transports">
    ///     <para>
    ///         This OPTIONAL member contains a hint as to how the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> might communicate with the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source-managing-authenticator">managing authenticator</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">public key credential</a> the caller is
    ///         referring to. The values SHOULD be members of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-authenticatortransport">AuthenticatorTransport</a> but <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST
    ///         ignore unknown values.
    ///     </para>
    ///     <para>
    ///         This mirrors the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredential-response">response</a>.<a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-gettransports">getTransports()</a> method of a
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#publickeycredential">PublicKeyCredential</a> structure created by a <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create">create()</a> operation. When
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-registering-a-new-credential">registering a new credential</a>, the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD store the value returned from
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-gettransports">getTransports()</a>. When creating a
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictdef-publickeycredentialdescriptor">PublicKeyCredentialDescriptor</a> for that credential, the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD retrieve that
    ///         stored value and set it as the value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialdescriptor-transports">transports</a> member.
    ///     </para>
    /// </param>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="type" /> contains a value that is not defined in <see cref="PublicKeyCredentialType" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="id" /> is <see langword="null" /></exception>
    /// <exception cref="InvalidEnumArgumentException">One of the elements in the <paramref name="transports" /> array contains a value not defined in <see cref="AuthenticatorTransport" /></exception>
    [JsonConstructor]
    public PublicKeyCredentialDescriptor(
        PublicKeyCredentialType type,
        byte[] id,
        AuthenticatorTransport[]? transports)
    {
        // type
        if (!Enum.IsDefined(type))
        {
            throw new InvalidEnumArgumentException(nameof(type), (int) type, typeof(PublicKeyCredentialType));
        }

        Type = type;

        // id
        ArgumentNullException.ThrowIfNull(id);
        Id = id;

        // transports
        if (transports?.Length > 0)
        {
            foreach (var transport in transports)
            {
                if (!Enum.IsDefined(transport))
                {
                    throw new InvalidEnumArgumentException(nameof(transports), (int) transport, typeof(AuthenticatorTransport));
                }
            }

            Transports = transports;
        }
    }

    /// <summary>
    ///     <para>
    ///         This member contains the type of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">public key credential</a> the caller is referring to. The value SHOULD be a member of
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialtype">PublicKeyCredentialType</a> but <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore any
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictdef-publickeycredentialdescriptor">PublicKeyCredentialDescriptor</a> with an unknown <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialdescriptor-type">type</a>.
    ///     </para>
    ///     <para>This mirrors the <a href="https://www.w3.org/TR/credential-management-1/#dom-credential-type">type</a> field of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#publickeycredential">PublicKeyCredential</a>.</para>
    /// </summary>
    [JsonPropertyName("type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public PublicKeyCredentialType Type { get; }

    /// <summary>
    ///     <para>This member contains the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id">credential ID</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">public key credential</a> the caller is referring to.</para>
    ///     <para>This mirrors the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredential-rawid">rawId</a> field of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#publickeycredential">PublicKeyCredential</a>.</para>
    /// </summary>
    [JsonPropertyName("id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    [JsonConverter(typeof(Base64UrlConverter))]
    public byte[] Id { get; }

    /// <summary>
    ///     <para>
    ///         This OPTIONAL member contains a hint as to how the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> might communicate with the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source-managing-authenticator">managing authenticator</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">public key credential</a> the caller is
    ///         referring to. The values SHOULD be members of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-authenticatortransport">AuthenticatorTransport</a> but <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST
    ///         ignore unknown values.
    ///     </para>
    ///     <para>
    ///         This mirrors the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredential-response">response</a>.<a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-gettransports">getTransports()</a> method of a
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#publickeycredential">PublicKeyCredential</a> structure created by a <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create">create()</a> operation. When
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-registering-a-new-credential">registering a new credential</a>, the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD store the value returned from
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorattestationresponse-gettransports">getTransports()</a>. When creating a
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictdef-publickeycredentialdescriptor">PublicKeyCredentialDescriptor</a> for that credential, the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD retrieve that
    ///         stored value and set it as the value of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialdescriptor-transports">transports</a> member.
    ///     </para>
    /// </summary>
    [JsonPropertyName("transports")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public AuthenticatorTransport[]? Transports { get; }
}
