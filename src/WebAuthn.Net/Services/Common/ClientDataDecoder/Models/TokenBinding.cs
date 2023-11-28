using System;
using System.ComponentModel;
using WebAuthn.Net.Services.Common.ClientDataDecoder.Models.Enums;

namespace WebAuthn.Net.Services.Common.ClientDataDecoder.Models;

/// <summary>
///     Token Binding dictionary
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictdef-tokenbinding">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.8.1. Client Data Used in WebAuthn Signatures (dictionary TokenBinding)</a>
///     </para>
/// </remarks>
public class TokenBinding
{
    /// <summary>
    ///     Constructs <see cref="TokenBinding" />.
    /// </summary>
    /// <param name="status">
    ///     <para>
    ///         This member SHOULD be a member of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-tokenbindingstatus">TokenBindingStatus</a> but <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore unknown
    ///         values, treating an unknown value as if the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#collectedclientdata-tokenbinding">tokenBinding</a> <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>. When known, this member is one of the
    ///         following:
    ///         <list type="table">
    ///             <item>
    ///                 <term>supported</term>
    ///                 <description>Indicates the client supports token binding, but it was not negotiated when communicating with the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>.</description>
    ///             </item>
    ///             <item>
    ///                 <term>present</term>
    ///                 <description>
    ///                     Indicates token binding was used when communicating with the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>. In this case, the
    ///                     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-tokenbinding-id">id</a> member MUST be present.
    ///                 </description>
    ///             </item>
    ///         </list>
    ///     </para>
    /// </param>
    /// <param name="id">
    ///     This member MUST be present if <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-tokenbinding-status">status</a> is <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-tokenbindingstatus-present">"present"</a>, and MUST be a base64url encoding of
    ///     the <a href="https://www.rfc-editor.org/rfc/rfc8471.html#section-3.2">Token Binding ID</a> that was used when communicating with the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>.
    /// </param>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="status" /> contains a value that is not defined in <see cref="TokenBindingStatus" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="id" /> is <see langword="null" /> when status is <see cref="TokenBindingStatus.Present" /></exception>
    /// <exception cref="ArgumentException"><paramref name="id" /> is empty when status is <see cref="TokenBindingStatus.Present" /></exception>
    public TokenBinding(TokenBindingStatus status, byte[]? id)
    {
        if (!Enum.IsDefined(typeof(TokenBindingStatus), status))
        {
            throw new InvalidEnumArgumentException(nameof(status), (int) status, typeof(TokenBindingStatus));
        }

        if (status == TokenBindingStatus.Present)
        {
            ArgumentNullException.ThrowIfNull(id);
            if (id.Length == 0)
            {
                throw new ArgumentException($"The {nameof(id)} must contain at least one element", nameof(id));
            }
        }

        Status = status;
        Id = id;
    }

    /// <summary>
    ///     <para>
    ///         This member SHOULD be a member of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-tokenbindingstatus">TokenBindingStatus</a> but <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore unknown
    ///         values, treating an unknown value as if the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#collectedclientdata-tokenbinding">tokenBinding</a> <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>. When known, this member is one of the
    ///         following:
    ///         <list type="table">
    ///             <item>
    ///                 <term>supported</term>
    ///                 <description>Indicates the client supports token binding, but it was not negotiated when communicating with the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>.</description>
    ///             </item>
    ///             <item>
    ///                 <term>present</term>
    ///                 <description>
    ///                     Indicates token binding was used when communicating with the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>. In this case, the
    ///                     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-tokenbinding-id">id</a> member MUST be present.
    ///                 </description>
    ///             </item>
    ///         </list>
    ///     </para>
    /// </summary>
    public TokenBindingStatus Status { get; }

    /// <summary>
    ///     This member MUST be present if <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-tokenbinding-status">status</a> is <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-tokenbindingstatus-present">"present"</a>, and MUST be a base64url encoding of
    ///     the <a href="https://www.rfc-editor.org/rfc/rfc8471.html#section-3.2">Token Binding ID</a> that was used when communicating with the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>.
    /// </summary>
    /// <remarks>
    ///     Obtaining a <a href="https://www.rfc-editor.org/rfc/rfc8471.html#section-3.2">Token Binding ID</a> is a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platform</a>-specific operation.
    /// </remarks>
    public byte[]? Id { get; }
}
