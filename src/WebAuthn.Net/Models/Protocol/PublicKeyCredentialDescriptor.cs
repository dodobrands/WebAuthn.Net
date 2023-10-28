using System;
using System.ComponentModel;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Models.Protocol;

/// <summary>
///     Credential Descriptor (dictionary PublicKeyCredentialDescriptor).
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-credential-descriptor">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.8.3. Credential Descriptor (dictionary PublicKeyCredentialDescriptor)</a>
///     </para>
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
    ///     <para>This mirrors the <a href="https://w3c.github.io/webappsec-credential-management/#dom-credential-type">type</a> field of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#publickeycredential">PublicKeyCredential</a>.</para>
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
    /// <exception cref="ArgumentException">The length of <paramref name="id" /> is less than 16</exception>
    /// <exception cref="ArgumentException">The length of <paramref name="id" /> is greater than 1023</exception>
    /// <exception cref="InvalidEnumArgumentException">One of the elements in the <paramref name="transports" /> array contains a value not defined in <see cref="AuthenticatorTransport" /></exception>
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
        if (id.Length < 16)
        {
            // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id
            // At least 16 bytes that include at least 100 bits of entropy
            throw new ArgumentException($"The minimum length of the {nameof(id)} is 16.", nameof(id));
        }

        if (id.Length > 1023)
        {
            // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id
            // At least 16 bytes that include at least 100 bits of entropy
            throw new ArgumentException($"The max length of the {nameof(id)} is 1023.", nameof(id));
        }

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
    ///     <para>This mirrors the <a href="https://w3c.github.io/webappsec-credential-management/#dom-credential-type">type</a> field of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#publickeycredential">PublicKeyCredential</a>.</para>
    /// </summary>
    public PublicKeyCredentialType Type { get; }

    /// <summary>
    ///     <para>This member contains the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id">credential ID</a> of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential">public key credential</a> the caller is referring to.</para>
    ///     <para>This mirrors the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredential-rawid">rawId</a> field of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#publickeycredential">PublicKeyCredential</a>.</para>
    /// </summary>
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
    public AuthenticatorTransport[]? Transports { get; }
}
