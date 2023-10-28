using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Models.Protocol.Json;

/// <summary>
///     Credential Descriptor (dictionary PublicKeyCredentialDescriptor).
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-credential-descriptor">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.8.3. Credential Descriptor (dictionary PublicKeyCredentialDescriptor)</a>
/// </remarks>
// ReSharper disable once InconsistentNaming
public class PublicKeyCredentialDescriptorJSON
{
    /// <summary>
    ///     Constructs <see cref="PublicKeyCredentialDescriptorJSON" />.
    /// </summary>
    /// <param name="id">This member contains the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id">credential ID</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">public key credential</a> the caller is referring to.</param>
    /// <param name="type">
    ///     This member contains the type of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">public key credential</a> the caller is referring to. The value SHOULD be a member of
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialtype">PublicKeyCredentialType</a> but <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore any
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictdef-publickeycredentialdescriptor">PublicKeyCredentialDescriptor</a> with an unknown <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialdescriptor-type">type</a>.
    /// </param>
    /// <param name="transports">
    ///     This OPTIONAL member contains a hint as to how the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> might communicate with the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source-managing-authenticator">managing authenticator</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">public key credential</a> the caller is
    ///     referring to. The values SHOULD be members of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-authenticatortransport">AuthenticatorTransport</a> but <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST
    ///     ignore unknown values.
    /// </param>
    [JsonConstructor]
    public PublicKeyCredentialDescriptorJSON(string id, string type, string[]? transports)
    {
        Id = id;
        Type = type;
        Transports = transports;
    }

    /// <summary>
    ///     <para>This member contains the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id">credential ID</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">public key credential</a> the caller is referring to.</para>
    ///     <para>This mirrors the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredential-rawid">rawId</a> field of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#publickeycredential">PublicKeyCredential</a>.</para>
    /// </summary>
    /// <remarks>
    ///     <para>Base64URLString</para>
    /// </remarks>
    [JsonPropertyName("id")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Id { get; }

    /// <summary>
    ///     <para>
    ///         This member contains the type of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">public key credential</a> the caller is referring to. The value SHOULD be a member of
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialtype">PublicKeyCredentialType</a> but <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore any
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictdef-publickeycredentialdescriptor">PublicKeyCredentialDescriptor</a> with an unknown <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialdescriptor-type">type</a>.
    ///     </para>
    ///     <para>This mirrors the <a href="https://w3c.github.io/webappsec-credential-management/#dom-credential-type">type</a> field of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#publickeycredential">PublicKeyCredential</a>.</para>
    /// </summary>
    /// <remarks>
    ///     <para>DOMString</para>
    /// </remarks>
    [JsonPropertyName("type")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Type { get; }

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
    /// <remarks>
    ///     <para>DOMString</para>
    /// </remarks>
    [JsonPropertyName("transports")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string[]? Transports { get; }
}
