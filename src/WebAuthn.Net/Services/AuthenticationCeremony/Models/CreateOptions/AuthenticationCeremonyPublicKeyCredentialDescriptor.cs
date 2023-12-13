using System;
using System.ComponentModel;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;

/// <summary>
///     Reduced representation of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictdef-publickeycredentialdescriptor">PublicKeyCredentialDescriptor</a> (does not contain
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialdescriptor-transports">transports</a>, as its value will be taken from the saved value) used to form a set of public key descriptors to be used in
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialrequestoptions-allowcredentials">allowCredentials</a> of the resulting
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-assertion-options">authentication ceremony options</a>.
/// </summary>
public class AuthenticationCeremonyPublicKeyCredentialDescriptor
{
    /// <summary>
    ///     Constructs <see cref="RegistrationCeremonyPublicKeyCredentialDescriptor" />.
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
    /// <exception cref="InvalidEnumArgumentException"><paramref name="type" /> contains a value that is not defined in <see cref="PublicKeyCredentialType" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="id" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException">The length of <paramref name="id" /> is less than 16</exception>
    /// <exception cref="ArgumentException">The length of <paramref name="id" /> is greater than 1023</exception>
    public AuthenticationCeremonyPublicKeyCredentialDescriptor(PublicKeyCredentialType type, byte[] id)
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
}
