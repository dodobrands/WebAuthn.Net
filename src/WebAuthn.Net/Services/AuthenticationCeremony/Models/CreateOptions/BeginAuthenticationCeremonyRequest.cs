using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text.Json;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Providers;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;

/// <summary>
///     A request containing the parameters for generating options for the authentication ceremony.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#dictionary-assertion-options">Web Authentication: An API for accessing Public Key Credentials Level 3 - Options for Assertion Generation (dictionary PublicKeyCredentialRequestOptions)</a>
/// </remarks>
public class BeginAuthenticationCeremonyRequest
{
    /// <summary>
    ///     Constructs <see cref="BeginAuthenticationCeremonyRequest" />.
    /// </summary>
    /// <param name="origins">
    ///     Parameters defining acceptable origins for the authentication ceremony. If <see langword="null" />, the only acceptable origin is the origin of the current request, computed by
    ///     <see cref="IRelyingPartyOriginProvider" />.
    /// </param>
    /// <param name="topOrigins">
    ///     Parameters defining acceptable topOrigins for the authentication ceremony - the origins of the top-level pages within which the Relying Party expects the ceremony to run in an iframe that is not same-origin with its ancestors. If
    ///     <see langword="null" />, the Relying Party doesn't expect to be embedded by other origins: client data with <c>topOrigin</c> is accepted only if <c>topOrigin</c> is equal to <c>origin</c>, and client data with <c>crossOrigin</c> set to
    ///     <see langword="true" /> but without <c>topOrigin</c> is rejected. If specified, client data with <c>crossOrigin</c> set to <see langword="true" /> is accepted, and <c>topOrigin</c>, when present, must be one of these origins.
    /// </param>
    /// <param name="userHandle">
    ///     <para>
    ///         A user handle is an identifier for a <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a>, specified by the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> as
    ///         <span><a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-user">user</a>.<a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-id">id</a></span> during
    ///         <a href="https://www.w3.org/TR/webauthn-3/#registration">registration</a>. <a href="https://www.w3.org/TR/webauthn-3/#discoverable-credential">Discoverable credentials</a> store this identifier and MUST return it as
    ///         <span><a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-response">response</a>.<a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-userhandle">userHandle</a></span> in
    ///         <a href="https://www.w3.org/TR/webauthn-3/#authentication-ceremony">authentication ceremonies</a> started with an <a href="https://infra.spec.whatwg.org/#list-empty">empty</a>
    ///         <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-allowcredentials">allowCredentials</a> argument.
    ///     </para>
    ///     <para>
    ///         The main use of the <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> is to identify the <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a> in such
    ///         <a href="https://www.w3.org/TR/webauthn-3/#authentication-ceremony">authentication ceremonies</a>, but the <a href="https://www.w3.org/TR/webauthn-3/#credential-id">credential ID</a> could be used instead. The main differences are that the
    ///         <a href="https://www.w3.org/TR/webauthn-3/#credential-id">credential ID</a> is chosen by the <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> and is unique for each credential, while the
    ///         <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> is chosen by the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> and ought to be the same for all
    ///         <a href="https://www.w3.org/TR/credential-management-1/#concept-credential">credentials</a> registered to the same <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a>.
    ///     </para>
    ///     <para>
    ///         <a href="https://www.w3.org/TR/webauthn-3/#authenticator">Authenticators</a> <a href="https://www.w3.org/TR/webauthn-3/#authenticator-credentials-map">map</a> pairs of <a href="https://www.w3.org/TR/webauthn-3/#rp-id">RP ID</a> and
    ///         <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> to <a href="https://www.w3.org/TR/webauthn-3/#public-key-credential-source">public key credential sources</a>. As a consequence, an authenticator will store at most one
    ///         <a href="https://www.w3.org/TR/webauthn-3/#discoverable-credential">discoverable credential</a> per <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> per <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a>. Therefore a
    ///         secondary use of the <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> is to allow <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticators</a> to know when to replace an existing
    ///         <a href="https://www.w3.org/TR/webauthn-3/#discoverable-credential">discoverable credential</a> with a new one during the <a href="https://www.w3.org/TR/webauthn-3/#registration-ceremony">registration ceremony</a>.
    ///     </para>
    ///     <para>
    ///         A user handle is an opaque <a href="https://infra.spec.whatwg.org/#byte-sequence">byte sequence</a> with a maximum size of 64 bytes, and is not meant to be displayed to the user. It MUST NOT contain personally identifying information, see
    ///         <a href="https://www.w3.org/TR/webauthn-3/#sctn-user-handle-privacy">"User Handle Contents"</a>.
    ///     </para>
    /// </param>
    /// <param name="challengeSize">
    ///     The size of the randomly generated <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-challenge">challenge</a> value.
    ///     <a href="https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges">The minimum allowed size is 16.</a>
    /// </param>
    /// <param name="timeout">
    ///     This OPTIONAL member specifies a time, in milliseconds, that the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> is willing to wait for the call to complete. The value is treated as a hint, and MAY be overridden by the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#client">client</a>.
    /// </param>
    /// <param name="allowCredentials">
    ///     <para>Includes parameters of allowed credentials for the authentication ceremony.</para>
    ///     <para>
    ///         This OPTIONAL member is used by the <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> to find <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticators</a> eligible for this
    ///         <a href="https://www.w3.org/TR/webauthn-3/#authentication-ceremony">authentication ceremony</a>. It can be used in two ways:
    ///         <list type="bullet">
    ///             <item>
    ///                 <description>
    ///                     <para>
    ///                         If the <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a> to authenticate is already identified (e.g., if the user has entered a username), then the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> SHOULD
    ///                         use this member to list <a href="https://www.w3.org/TR/webauthn-3/#credential-descriptor-for-a-credential-record">credential descriptors for credential records</a> in the <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a>. This
    ///                         SHOULD usually include all <a href="https://www.w3.org/TR/webauthn-3/#credential-record">credential records</a> in the <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a>.
    ///                     </para>
    ///                     <para>
    ///                         The <a href="https://infra.spec.whatwg.org/#list-item">items</a> SHOULD specify <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialdescriptor-transports">transports</a> whenever possible. This helps the
    ///                         <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> optimize the user experience for any given situation. Also note that the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> does not need to filter the list when
    ///                         requesting <a href="https://www.w3.org/TR/webauthn-3/#user-verification">user verification</a> — the <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> will automatically ignore non-eligible credentials if
    ///                         <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-userverification">userVerification</a> is set to <a href="https://www.w3.org/TR/webauthn-3/#dom-userverificationrequirement-required">required</a>.
    ///                     </para>
    ///                     <para>See also the <a href="https://www.w3.org/TR/webauthn-3/#sctn-credential-id-privacy-leak">"Privacy leak via credential IDs"</a> privacy consideration.</para>
    ///                 </description>
    ///             </item>
    ///             <item>
    ///                 <description>
    ///                     <para>
    ///                         If the <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a> to authenticate is not already identified, then the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> MAY leave this member
    ///                         <a href="https://infra.spec.whatwg.org/#list-empty">empty</a> or unspecified. In this case, only <a href="https://www.w3.org/TR/webauthn-3/#discoverable-credential">discoverable credentials</a> will be utilized in this
    ///                         <a href="https://www.w3.org/TR/webauthn-3/#authentication-ceremony">authentication ceremony</a>, and the <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a> MAY be identified by the
    ///                         <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-userhandle">userHandle</a> of the resulting <a href="https://www.w3.org/TR/webauthn-3/#authenticatorassertionresponse">AuthenticatorAssertionResponse</a>. If the available
    ///                         <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticators</a> <a href="https://www.w3.org/TR/webauthn-3/#contains">contain</a> more than one <a href="https://www.w3.org/TR/webauthn-3/#discoverable-credential">discoverable credential</a>
    ///                         <a href="https://www.w3.org/TR/webauthn-3/#scope">scoped</a> to the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a>, the credentials are displayed by the
    ///                         <a href="https://www.w3.org/TR/webauthn-3/#client-platform">client platform</a> or <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> for the user to select from (see
    ///                         <a href="https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion">"The authenticatorGetAssertion Operation"</a>).
    ///                     </para>
    ///                 </description>
    ///             </item>
    ///         </list>
    ///     </para>
    ///     <para>If not <a href="https://infra.spec.whatwg.org/#list-empty">empty</a>, the client MUST return an error if none of the listed credentials can be used.</para>
    ///     <para>The list is ordered in descending order of preference: the first item in the list is the most preferred credential, and the last is the least preferred.</para>
    /// </param>
    /// <param name="userVerification">
    ///     <para>
    ///         This OPTIONAL member specifies the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party’s</a> requirements regarding <a href="https://www.w3.org/TR/webauthn-3/#user-verification">user verification</a> for the
    ///         <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-get">get()</a> operation. The value SHOULD be a member of <a href="https://www.w3.org/TR/webauthn-3/#enumdef-userverificationrequirement">UserVerificationRequirement</a> but
    ///         <a href="https://www.w3.org/TR/webauthn-3/#client-platform">client platforms</a> MUST ignore unknown values, treating an unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>. Eligible authenticators are filtered to only
    ///         those capable of satisfying this requirement.
    ///     </para>
    ///     <para>
    ///         See <a href="https://www.w3.org/TR/webauthn-3/#enumdef-userverificationrequirement">UserVerificationRequirement</a> for the description of <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-userverification">userVerification’s</a> values and
    ///         semantics.
    ///     </para>
    /// </param>
    /// <param name="hints">
    ///     This OPTIONAL member contains zero or more elements from <a href="https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialhint">PublicKeyCredentialHint</a> to guide the user agent in interacting with the user.
    /// </param>
    /// <param name="extensions">
    ///     <para>
    ///         The <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> MAY use this OPTIONAL member to provide <a href="https://www.w3.org/TR/webauthn-3/#client-extension-input">client extension inputs</a> requesting additional processing by the
    ///         <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> and <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a>.
    ///     </para>
    ///     <para>
    ///         The extensions framework is defined in <a href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">"WebAuthn Extensions"</a>. Some extensions are defined in <a href="https://www.w3.org/TR/webauthn-3/#sctn-defined-extensions">"Defined Extensions"</a>; consult the
    ///         <a href="https://www.iana.org/assignments/webauthn/">IANA "WebAuthn Extension Identifiers" registry</a> established by <a href="https://www.rfc-editor.org/rfc/rfc8809">RFC8809</a> for an up-to-date list of registered
    ///         <a href="https://www.w3.org/TR/webauthn-3/#webauthn-extensions">WebAuthn Extensions</a>.
    ///     </para>
    /// </param>
    /// <exception cref="ArgumentException"><paramref name="challengeSize" /> is less than 16</exception>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="userVerification" /> contains a value that is not defined in <see cref="UserVerificationRequirement" /></exception>
    /// <exception cref="InvalidEnumArgumentException">One of the elements in the <paramref name="hints" /> array contains a value not defined in <see cref="PublicKeyCredentialHints" /></exception>
    public BeginAuthenticationCeremonyRequest(
        AuthenticationCeremonyOriginParameters? origins,
        AuthenticationCeremonyOriginParameters? topOrigins,
        byte[]? userHandle,
        int challengeSize,
        uint? timeout,
        AuthenticationCeremonyIncludeCredentials? allowCredentials,
        UserVerificationRequirement? userVerification,
        PublicKeyCredentialHints[]? hints,
        Dictionary<string, JsonElement>? extensions)
    {
        // origins
        Origins = origins;

        // topOrigins
        TopOrigins = topOrigins;

        //userHandle
        UserHandle = userHandle;

        // challengeSize
        if (challengeSize < 16)
        {
            throw new ArgumentException($"The minimum value of {nameof(challengeSize)} is 16.", nameof(challengeSize));
        }

        ChallengeSize = challengeSize;

        // timeout
        Timeout = timeout;

        // allowCredentials
        AllowCredentials = allowCredentials;

        // userVerification
        if (userVerification.HasValue)
        {
            if (!Enum.IsDefined(userVerification.Value))
            {
                throw new InvalidEnumArgumentException(nameof(userVerification), (int) userVerification.Value, typeof(UserVerificationRequirement));
            }

            UserVerification = userVerification.Value;
        }

        // hints
        if (hints?.Length > 0)
        {
            foreach (var hint in hints)
            {
                if (!Enum.IsDefined(hint))
                {
                    throw new InvalidEnumArgumentException(nameof(hints), (int) hint, typeof(PublicKeyCredentialHints));
                }
            }

            Hints = hints;
        }

        // extensions
        Extensions = extensions;
    }

    /// <summary>
    ///     Parameters defining acceptable origins for the authentication ceremony. If <see langword="null" />, the only acceptable origin is the origin of the current request, computed by <see cref="IRelyingPartyOriginProvider" />.
    /// </summary>
    public AuthenticationCeremonyOriginParameters? Origins { get; }

    /// <summary>
    ///     Parameters defining acceptable topOrigins for the authentication ceremony - the origins of the top-level pages within which the Relying Party expects the ceremony to run in an iframe that is not same-origin with its ancestors. If
    ///     <see langword="null" />, the Relying Party doesn't expect to be embedded by other origins: client data with <c>topOrigin</c> is accepted only if <c>topOrigin</c> is equal to <c>origin</c>, and client data with <c>crossOrigin</c> set to
    ///     <see langword="true" /> but without <c>topOrigin</c> is rejected. If specified, client data with <c>crossOrigin</c> set to <see langword="true" /> is accepted, and <c>topOrigin</c>, when present, must be one of these origins.
    /// </summary>
    public AuthenticationCeremonyOriginParameters? TopOrigins { get; }

    /// <summary>
    ///     <para>
    ///         A user handle is an identifier for a <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a>, specified by the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> as
    ///         <span><a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-user">user</a>.<a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-id">id</a></span> during
    ///         <a href="https://www.w3.org/TR/webauthn-3/#registration">registration</a>. <a href="https://www.w3.org/TR/webauthn-3/#discoverable-credential">Discoverable credentials</a> store this identifier and MUST return it as
    ///         <span><a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-response">response</a>.<a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-userhandle">userHandle</a></span> in
    ///         <a href="https://www.w3.org/TR/webauthn-3/#authentication-ceremony">authentication ceremonies</a> started with an <a href="https://infra.spec.whatwg.org/#list-empty">empty</a>
    ///         <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-allowcredentials">allowCredentials</a> argument.
    ///     </para>
    ///     <para>
    ///         The main use of the <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> is to identify the <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a> in such
    ///         <a href="https://www.w3.org/TR/webauthn-3/#authentication-ceremony">authentication ceremonies</a>, but the <a href="https://www.w3.org/TR/webauthn-3/#credential-id">credential ID</a> could be used instead. The main differences are that the
    ///         <a href="https://www.w3.org/TR/webauthn-3/#credential-id">credential ID</a> is chosen by the <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> and is unique for each credential, while the
    ///         <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> is chosen by the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> and ought to be the same for all
    ///         <a href="https://www.w3.org/TR/credential-management-1/#concept-credential">credentials</a> registered to the same <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a>.
    ///     </para>
    ///     <para>
    ///         <a href="https://www.w3.org/TR/webauthn-3/#authenticator">Authenticators</a> <a href="https://www.w3.org/TR/webauthn-3/#authenticator-credentials-map">map</a> pairs of <a href="https://www.w3.org/TR/webauthn-3/#rp-id">RP ID</a> and
    ///         <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> to <a href="https://www.w3.org/TR/webauthn-3/#public-key-credential-source">public key credential sources</a>. As a consequence, an authenticator will store at most one
    ///         <a href="https://www.w3.org/TR/webauthn-3/#discoverable-credential">discoverable credential</a> per <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> per <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a>. Therefore a
    ///         secondary use of the <a href="https://www.w3.org/TR/webauthn-3/#user-handle">user handle</a> is to allow <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticators</a> to know when to replace an existing
    ///         <a href="https://www.w3.org/TR/webauthn-3/#discoverable-credential">discoverable credential</a> with a new one during the <a href="https://www.w3.org/TR/webauthn-3/#registration-ceremony">registration ceremony</a>.
    ///     </para>
    ///     <para>
    ///         A user handle is an opaque <a href="https://infra.spec.whatwg.org/#byte-sequence">byte sequence</a> with a maximum size of 64 bytes, and is not meant to be displayed to the user. It MUST NOT contain personally identifying information, see
    ///         <a href="https://www.w3.org/TR/webauthn-3/#sctn-user-handle-privacy">"User Handle Contents"</a>.
    ///     </para>
    /// </summary>
    public byte[]? UserHandle { get; }

    /// <summary>
    ///     The size of the randomly generated <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-challenge">challenge</a> value. <a href="https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges">The minimum allowed size is 16.</a>
    /// </summary>
    public int ChallengeSize { get; }

    /// <summary>
    ///     This OPTIONAL member specifies a time, in milliseconds, that the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> is willing to wait for the call to complete. The value is treated as a hint, and MAY be overridden by the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#client">client</a>.
    /// </summary>
    public uint? Timeout { get; }

    /// <summary>
    ///     <para>Includes parameters of allowed credentials for the authentication ceremony.</para>
    ///     <para>
    ///         This OPTIONAL member is used by the <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> to find <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticators</a> eligible for this
    ///         <a href="https://www.w3.org/TR/webauthn-3/#authentication-ceremony">authentication ceremony</a>. It can be used in two ways:
    ///         <list type="bullet">
    ///             <item>
    ///                 <description>
    ///                     <para>
    ///                         If the <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a> to authenticate is already identified (e.g., if the user has entered a username), then the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> SHOULD
    ///                         use this member to list <a href="https://www.w3.org/TR/webauthn-3/#credential-descriptor-for-a-credential-record">credential descriptors for credential records</a> in the <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a>. This
    ///                         SHOULD usually include all <a href="https://www.w3.org/TR/webauthn-3/#credential-record">credential records</a> in the <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a>.
    ///                     </para>
    ///                     <para>
    ///                         The <a href="https://infra.spec.whatwg.org/#list-item">items</a> SHOULD specify <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialdescriptor-transports">transports</a> whenever possible. This helps the
    ///                         <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> optimize the user experience for any given situation. Also note that the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> does not need to filter the list when
    ///                         requesting <a href="https://www.w3.org/TR/webauthn-3/#user-verification">user verification</a> — the <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> will automatically ignore non-eligible credentials if
    ///                         <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-userverification">userVerification</a> is set to <a href="https://www.w3.org/TR/webauthn-3/#dom-userverificationrequirement-required">required</a>.
    ///                     </para>
    ///                     <para>
    ///                         See also the <a href="https://www.w3.org/TR/webauthn-3/#sctn-credential-id-privacy-leak">"Privacy leak via credential IDs"</a> privacy consideration.
    ///                     </para>
    ///                 </description>
    ///             </item>
    ///             <item>
    ///                 <description>
    ///                     <para>
    ///                         If the <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a> to authenticate is not already identified, then the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> MAY leave this member
    ///                         <a href="https://infra.spec.whatwg.org/#list-empty">empty</a> or unspecified. In this case, only <a href="https://www.w3.org/TR/webauthn-3/#discoverable-credential">discoverable credentials</a> will be utilized in this
    ///                         <a href="https://www.w3.org/TR/webauthn-3/#authentication-ceremony">authentication ceremony</a>, and the <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a> MAY be identified by the
    ///                         <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-userhandle">userHandle</a> of the resulting <a href="https://www.w3.org/TR/webauthn-3/#authenticatorassertionresponse">AuthenticatorAssertionResponse</a>. If the available
    ///                         <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticators</a> <a href="https://www.w3.org/TR/webauthn-3/#contains">contain</a> more than one <a href="https://www.w3.org/TR/webauthn-3/#discoverable-credential">discoverable credential</a>
    ///                         <a href="https://www.w3.org/TR/webauthn-3/#scope">scoped</a> to the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a>, the credentials are displayed by the
    ///                         <a href="https://www.w3.org/TR/webauthn-3/#client-platform">client platform</a> or <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> for the user to select from (see
    ///                         <a href="https://www.w3.org/TR/webauthn-3/#sctn-op-get-assertion">"The authenticatorGetAssertion Operation"</a>).
    ///                     </para>
    ///                 </description>
    ///             </item>
    ///         </list>
    ///     </para>
    ///     <para>If not <a href="https://infra.spec.whatwg.org/#list-empty">empty</a>, the client MUST return an error if none of the listed credentials can be used.</para>
    ///     <para>The list is ordered in descending order of preference: the first item in the list is the most preferred credential, and the last is the least preferred.</para>
    /// </summary>
    public AuthenticationCeremonyIncludeCredentials? AllowCredentials { get; }

    /// <summary>
    ///     <para>
    ///         This OPTIONAL member specifies the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party’s</a> requirements regarding <a href="https://www.w3.org/TR/webauthn-3/#user-verification">user verification</a> for the
    ///         <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-get">get()</a> operation. The value SHOULD be a member of <a href="https://www.w3.org/TR/webauthn-3/#enumdef-userverificationrequirement">UserVerificationRequirement</a> but
    ///         <a href="https://www.w3.org/TR/webauthn-3/#client-platform">client platforms</a> MUST ignore unknown values, treating an unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>. Eligible authenticators are filtered to only
    ///         those capable of satisfying this requirement.
    ///     </para>
    ///     <para>
    ///         See <a href="https://www.w3.org/TR/webauthn-3/#enumdef-userverificationrequirement">UserVerificationRequirement</a> for the description of <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-userverification">userVerification’s</a> values and
    ///         semantics.
    ///     </para>
    /// </summary>
    /// <remarks>defaulting to "preferred"</remarks>
    public UserVerificationRequirement? UserVerification { get; }

    /// <summary>
    ///     This OPTIONAL member contains zero or more elements from <a href="https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialhint">PublicKeyCredentialHint</a> to guide the user agent in interacting with the user.
    /// </summary>
    /// <remarks>
    ///     defaulting to []
    /// </remarks>
    public PublicKeyCredentialHints[]? Hints { get; }

    /// <summary>
    ///     <para>
    ///         The <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> MAY use this OPTIONAL member to provide <a href="https://www.w3.org/TR/webauthn-3/#client-extension-input">client extension inputs</a> requesting additional processing by the
    ///         <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> and <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a>.
    ///     </para>
    ///     <para>
    ///         The extensions framework is defined in <a href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">"WebAuthn Extensions"</a>. Some extensions are defined in <a href="https://www.w3.org/TR/webauthn-3/#sctn-defined-extensions">"Defined Extensions"</a>; consult the
    ///         <a href="https://www.iana.org/assignments/webauthn/">IANA "WebAuthn Extension Identifiers" registry</a> established by <a href="https://www.rfc-editor.org/rfc/rfc8809">RFC8809</a> for an up-to-date list of registered
    ///         <a href="https://www.w3.org/TR/webauthn-3/#webauthn-extensions">WebAuthn Extensions</a>.
    ///     </para>
    /// </summary>
    public Dictionary<string, JsonElement>? Extensions { get; }
}
