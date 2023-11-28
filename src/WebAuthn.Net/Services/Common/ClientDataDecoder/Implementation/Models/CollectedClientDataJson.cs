using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.Common.ClientDataDecoder.Implementation.Models;

/// <summary>
///     Client Data Used in <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#webauthn-signature">WebAuthn Signatures</a> (dictionary CollectedClientData)
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-client-data">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.8.1. Client Data Used in WebAuthn Signatures (dictionary CollectedClientData)</a>
///     </para>
/// </remarks>
public class CollectedClientDataJson
{
    /// <summary>
    ///     Constructs <see cref="CollectedClientDataJson" />.
    /// </summary>
    /// <param name="type">
    ///     This member contains the string "webauthn.create" when creating new credentials, and "webauthn.get" when getting an assertion from an existing credential. The purpose of this member is to prevent certain types of signature confusion attacks (where an attacker
    ///     substitutes one legitimate signature for another).
    /// </param>
    /// <param name="challenge">
    ///     This member contains the base64url encoding of the challenge provided by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>. See the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-cryptographic-challenges">§13.4.3 Cryptographic Challenges</a> security consideration.
    /// </param>
    /// <param name="origin">
    ///     This member contains the fully qualified <a href="https://html.spec.whatwg.org/multipage/browsers.html#concept-origin">origin</a> of the requester, as provided to the authenticator by the client, in the syntax defined by
    ///     <a href="https://www.rfc-editor.org/rfc/rfc6454.html">[RFC6454]</a>.
    /// </param>
    /// <param name="topOrigin">
    ///     This OPTIONAL member contains the fully qualified <a href="https://html.spec.whatwg.org/multipage/webappapis.html#concept-environment-top-level-origin">top-level origin</a> of the requester, in the syntax defined by
    ///     <a href="https://www.rfc-editor.org/rfc/rfc6454.html">[RFC6454]</a>. It is set only if the call was made from context that is not <a href="https://w3c.github.io/webappsec-credential-management/#same-origin-with-its-ancestors">same-origin with its ancestors</a>, i.e. if
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-collectedclientdata-crossorigin">crossOrigin</a> is true.
    /// </param>
    /// <param name="crossOrigin">This OPTIONAL member contains the inverse of the sameOriginWithAncestors argument value that was passed into the <a href="https://tc39.es/ecma262/#sec-object-internal-methods-and-internal-slots">internal method</a>.</param>
    /// <param name="tokenBinding">
    ///     This OPTIONAL member contains information about the state of the <a href="https://www.rfc-editor.org/rfc/rfc8471.html">Token Binding protocol</a> used when communicating with the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>. Its absence indicates that the client doesn't support token binding.
    /// </param>
    [JsonConstructor]
    public CollectedClientDataJson(
        string type,
        string challenge,
        string origin,
        string? topOrigin,
        bool? crossOrigin,
        TokenBindingJson? tokenBinding)
    {
        Type = type;
        Challenge = challenge;
        Origin = origin;
        TopOrigin = topOrigin;
        CrossOrigin = crossOrigin;
        TokenBinding = tokenBinding;
    }

    /// <summary>
    ///     This member contains the string "webauthn.create" when creating new credentials, and "webauthn.get" when getting an assertion from an existing credential. The purpose of this member is to prevent certain types of signature confusion attacks (where an attacker substitutes one
    ///     legitimate signature for another).
    /// </summary>
    [JsonPropertyName("type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string Type { get; }

    /// <summary>
    ///     This member contains the base64url encoding of the challenge provided by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>. See the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-cryptographic-challenges">§13.4.3 Cryptographic Challenges</a> security consideration.
    /// </summary>
    [JsonPropertyName("challenge")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Challenge { get; }

    /// <summary>
    ///     This member contains the fully qualified <a href="https://html.spec.whatwg.org/multipage/browsers.html#concept-origin">origin</a> of the requester, as provided to the authenticator by the client, in the syntax defined by
    ///     <a href="https://www.rfc-editor.org/rfc/rfc6454.html">[RFC6454]</a>.
    /// </summary>
    [JsonPropertyName("origin")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string Origin { get; }

    /// <summary>
    ///     This OPTIONAL member contains the fully qualified <a href="https://html.spec.whatwg.org/multipage/webappapis.html#concept-environment-top-level-origin">top-level origin</a> of the requester, in the syntax defined by
    ///     <a href="https://www.rfc-editor.org/rfc/rfc6454.html">[RFC6454]</a>. It is set only if the call was made from context that is not <a href="https://w3c.github.io/webappsec-credential-management/#same-origin-with-its-ancestors">same-origin with its ancestors</a>, i.e. if
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-collectedclientdata-crossorigin">crossOrigin</a> is true.
    /// </summary>
    [JsonPropertyName("topOrigin")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? TopOrigin { get; }

    /// <summary>
    ///     This OPTIONAL member contains the inverse of the sameOriginWithAncestors argument value that was passed into the <a href="https://tc39.es/ecma262/#sec-object-internal-methods-and-internal-slots">internal method</a>.
    /// </summary>
    [JsonPropertyName("crossOrigin")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool? CrossOrigin { get; }

    /// <summary>
    ///     This OPTIONAL member contains information about the state of the <a href="https://www.rfc-editor.org/rfc/rfc8471.html">Token Binding protocol</a> used when communicating with the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>.
    ///     Its absence indicates that the client doesn't support token binding.
    /// </summary>
    /// <remarks>
    ///     While <a href="https://www.rfc-editor.org/rfc/rfc8471.html">Token Binding</a> was present in Level 1 and Level 2 of WebAuthn, its use is not expected in Level 3. The
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#collectedclientdata-tokenbinding">tokenBinding</a> field is reserved so that it will not be reused for a different purpose.
    /// </remarks>
    [JsonPropertyName("tokenBinding")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public TokenBindingJson? TokenBinding { get; }
}
