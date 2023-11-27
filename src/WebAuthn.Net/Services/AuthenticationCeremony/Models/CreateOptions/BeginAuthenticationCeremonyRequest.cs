using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text.Json;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;

/// <summary>
///     A request containing the parameters for generating options for the authentication ceremony.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-assertion-options">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.5. Options for Assertion Generation (dictionary PublicKeyCredentialRequestOptions)</a>
/// </remarks>
public class BeginAuthenticationCeremonyRequest
{
    /// <summary>
    ///     Constructs <see cref="BeginAuthenticationCeremonyRequest" />.
    /// </summary>
    /// <param name="origins">Parameters defining acceptable origins for the registration ceremony.</param>
    /// <param name="topOrigins">Parameters defining acceptable topOrigins (iframe that is not same-origin with its ancestors) for the registration ceremony.</param>
    /// <param name="userHandle">
    ///     <para>
    ///         A <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> is an identifier for a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>, specified by the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> as <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-user">user</a>.
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-id">id</a> during <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration">registration</a>.
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">Discoverable credentials</a> store this identifier and MUST return it as <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredential-response">response</a>.
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorassertionresponse-userhandle">userHandle</a> in <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremonies</a> started with an
    ///         <a href="https://infra.spec.whatwg.org/#list-empty">empty</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialrequestoptions-allowcredentials">allowCredentials</a> argument.
    ///     </para>
    ///     <para>
    ///         The main use of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> is to identify the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> in such
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremonies</a>, but the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id">credential ID</a> could be used instead. The main differences are that
    ///         the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id">credential ID</a> is chosen by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> and is unique for each credential, while the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> is chosen by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> and ought to be the same for all
    ///         <a href="https://w3c.github.io/webappsec-credential-management/#concept-credential">credentials</a> registered to the same <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>.
    ///     </para>
    ///     <para>
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">Authenticators</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-credentials-map">map</a> pairs of
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#rp-id">RP ID</a> and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> to
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential sources</a>. As a consequence, an authenticator will store at most one
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credential</a> per <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> per
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>. Therefore a secondary use of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> is to allow
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticators</a> to know when to replace an existing <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credential</a> with a new one during the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration-ceremony">registration ceremony</a>.
    ///     </para>
    ///     <para>
    ///         A user handle is an opaque <a href="https://infra.spec.whatwg.org/#byte-sequence">byte sequence</a> with a maximum size of 64 bytes, and is not meant to be displayed to the user. It MUST NOT contain personally identifying information, see
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-user-handle-privacy">§14.6.1 User Handle Contents</a>.
    ///     </para>
    /// </param>
    /// <param name="challengeSize">
    ///     The size of the randomly generated <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-challenge">challenge</a> value.
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-cryptographic-challenges">The minimum allowed size is 16.</a>
    /// </param>
    /// <param name="timeout">
    ///     This OPTIONAL member specifies a time, in milliseconds, that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> is willing to wait for the call to complete. The value is treated as a hint, and MAY be overridden by the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a>.
    /// </param>
    /// <param name="allowCredentials">
    ///     <summary>
    ///         <para>Includes parameters of allowed credentials for the authentication ceremony.</para>
    ///         <para>
    ///             This OPTIONAL member is used by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> to find <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticators</a> eligible for this
    ///             <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremony</a>. It can be used in two ways:
    ///             <list type="bullet">
    ///                 <item>
    ///                     <description>
    ///                         <para>
    ///                             If the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> to authenticate is already identified (e.g., if the user has entered a username), then the
    ///                             <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD use this member to list
    ///                             <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-descriptor-for-a-credential-record">credential descriptors for credential records</a> in the
    ///                             <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>. This SHOULD usually include all <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">credential records</a> in the
    ///                             <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>.
    ///                         </para>
    ///                         <para>
    ///                             The <a href="https://infra.spec.whatwg.org/#list-item">items</a> SHOULD specify <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialdescriptor-transports">transports</a> whenever possible. This helps the
    ///                             <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> optimize the user experience for any given situation. Also note that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> does
    ///                             not need to filter the list when requesting <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a> — the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> will automatically
    ///                             ignore non-eligible credentials if <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialrequestoptions-userverification">userVerification</a> is set to
    ///                             <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-userverificationrequirement-required">required</a>.
    ///                         </para>
    ///                         <para>
    ///                             See also the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-credential-id-privacy-leak">§14.6.3 Privacy leak via credential IDs</a> privacy consideration.
    ///                         </para>
    ///                     </description>
    ///                 </item>
    ///                 <item>
    ///                     <description>
    ///                         <para>
    ///                             If the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> to authenticate is not already identified, then the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY
    ///                             leave this member <a href="https://infra.spec.whatwg.org/#list-empty">empty</a> or unspecified. In this case, only <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credentials</a> will be utilized in
    ///                             this <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremony</a>, and the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> MAY be identified by the
    ///                             <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorassertionresponse-userhandle">userHandle</a> of the resulting
    ///                             <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticatorassertionresponse">AuthenticatorAssertionResponse</a>. If the available <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticators</a>
    ///                             <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#contains">contain</a> more than one <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credential</a>
    ///                             <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#scope">scoped</a> to the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>, the credentials are displayed by the
    ///                             <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platform</a> or <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> for the user to select from (see
    ///                             <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticatorGetAssertion-prompt-select-credential">step 7</a> of
    ///                             <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-op-get-assertion">§6.3.3 The authenticatorGetAssertion Operation</a>).
    ///                         </para>
    ///                     </description>
    ///                 </item>
    ///             </list>
    ///         </para>
    ///         <para>If not <a href="https://infra.spec.whatwg.org/#list-empty">empty</a>, the client MUST return an error if none of the listed credentials can be used.</para>
    ///         <para>The list is ordered in descending order of preference: the first item in the list is the most preferred credential, and the last is the least preferred.</para>
    ///     </summary>
    /// </param>
    /// <param name="userVerification">
    ///     This OPTIONAL member specifies the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party's</a> requirements regarding <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a> for the
    ///     <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get">get()</a> operation. The value SHOULD be a member of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-userverificationrequirement">UserVerificationRequirement</a>
    ///     but <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore unknown values, treating an unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>. Eligible authenticators are
    ///     filtered to only those capable of satisfying this requirement.
    /// </param>
    /// <param name="hints">
    ///     This OPTIONAL member contains zero or more elements from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialhints">PublicKeyCredentialHints</a> to guide the user agent in interacting with the user.
    /// </param>
    /// <param name="attestation">
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY use this OPTIONAL member to specify a preference regarding <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-conveyance">attestation conveyance</a>. Its
    ///     value SHOULD be a member of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-attestationconveyancepreference">AttestationConveyancePreference</a>. <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">Client platforms</a> MUST ignore
    ///     unknown values, treating an unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    /// </param>
    /// <param name="attestationFormats">
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY use this OPTIONAL member to specify a preference regarding the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation">attestation</a> statement format used
    ///     by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>. Values SHOULD be taken from the <a href="https://www.iana.org/assignments/webauthn/webauthn.xhtml">IANA "WebAuthn Attestation Statement Format Identifiers" registry</a>
    ///     established by <a href="https://www.rfc-editor.org/rfc/rfc8809.html">RFC 8809</a>. Values are ordered from most preferable to least preferable. This parameter is advisory and the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> MAY
    ///     use an attestation statement not enumerated in this parameter.
    /// </param>
    /// <param name="extensions">
    ///     <para>
    ///         The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY use this OPTIONAL member to provide <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-extension-input">client extension inputs</a> requesting additional
    ///         processing by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>.
    ///     </para>
    ///     <para>
    ///         The extensions framework is defined in <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-extensions">§9 WebAuthn Extensions</a>. Some extensions are defined in
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-defined-extensions">§10 Defined Extensions</a>; consult the <a href="https://www.iana.org/assignments/webauthn/webauthn.xhtml">IANA "WebAuthn Extension Identifiers" registry</a> established by
    ///         <a href="https://www.rfc-editor.org/rfc/rfc8809.html">RFC 8809</a> for an up-to-date list of registered <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#webauthn-extensions">WebAuthn Extensions</a>.
    ///     </para>
    /// </param>
    /// <exception cref="ArgumentException"><paramref name="challengeSize" /> is less than 16</exception>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="userVerification" /> contains a value that is not defined in <see cref="UserVerificationRequirement" /></exception>
    /// <exception cref="InvalidEnumArgumentException">One of the elements in the <paramref name="hints" /> array contains a value not defined in <see cref="PublicKeyCredentialHints" /></exception>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="attestation" /> contains a value that is not defined in <see cref="AttestationConveyancePreference" /></exception>
    /// <exception cref="InvalidEnumArgumentException">One of the elements in the <paramref name="attestationFormats" /> array contains a value not defined in <see cref="AttestationStatementFormat" /></exception>
    public BeginAuthenticationCeremonyRequest(
        AuthenticationCeremonyOriginParameters? origins,
        AuthenticationCeremonyOriginParameters? topOrigins,
        byte[]? userHandle,
        int challengeSize,
        uint? timeout,
        AuthenticationCeremonyIncludeCredentials? allowCredentials,
        UserVerificationRequirement? userVerification,
        PublicKeyCredentialHints[]? hints,
        AttestationConveyancePreference? attestation,
        AttestationStatementFormat[]? attestationFormats,
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

        // attestation
        if (attestation.HasValue)
        {
            if (!Enum.IsDefined(attestation.Value))
            {
                throw new InvalidEnumArgumentException(nameof(attestation), (int) attestation.Value, typeof(AttestationConveyancePreference));
            }

            Attestation = attestation.Value;
        }

        // attestationFormats
        if (attestationFormats?.Length > 0)
        {
            foreach (var attestationFormat in attestationFormats)
            {
                if (!Enum.IsDefined(attestationFormat))
                {
                    throw new InvalidEnumArgumentException(nameof(attestationFormats), (int) attestationFormat, typeof(AttestationStatementFormat));
                }
            }

            AttestationFormats = attestationFormats;
        }

        // extensions
        Extensions = extensions;
    }

    /// <summary>
    ///     Parameters defining acceptable origins for the registration ceremony.
    /// </summary>
    public AuthenticationCeremonyOriginParameters? Origins { get; }

    /// <summary>
    ///     Parameters defining acceptable topOrigins (iframe that is not same-origin with its ancestors) for the registration ceremony.
    /// </summary>
    public AuthenticationCeremonyOriginParameters? TopOrigins { get; }

    /// <summary>
    ///     <para>
    ///         A <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> is an identifier for a <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>, specified by the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> as <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-user">user</a>.
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-id">id</a> during <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration">registration</a>.
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">Discoverable credentials</a> store this identifier and MUST return it as <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredential-response">response</a>.
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorassertionresponse-userhandle">userHandle</a> in <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremonies</a> started with an
    ///         <a href="https://infra.spec.whatwg.org/#list-empty">empty</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialrequestoptions-allowcredentials">allowCredentials</a> argument.
    ///     </para>
    ///     <para>
    ///         The main use of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> is to identify the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> in such
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremonies</a>, but the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id">credential ID</a> could be used instead. The main differences are that
    ///         the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-id">credential ID</a> is chosen by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> and is unique for each credential, while the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> is chosen by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> and ought to be the same for all
    ///         <a href="https://w3c.github.io/webappsec-credential-management/#concept-credential">credentials</a> registered to the same <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>.
    ///     </para>
    ///     <para>
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">Authenticators</a> <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator-credentials-map">map</a> pairs of
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#rp-id">RP ID</a> and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> to
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#public-key-credential-source">public key credential sources</a>. As a consequence, an authenticator will store at most one
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credential</a> per <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> per
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>. Therefore a secondary use of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-handle">user handle</a> is to allow
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticators</a> to know when to replace an existing <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credential</a> with a new one during the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration-ceremony">registration ceremony</a>.
    ///     </para>
    ///     <para>
    ///         A user handle is an opaque <a href="https://infra.spec.whatwg.org/#byte-sequence">byte sequence</a> with a maximum size of 64 bytes, and is not meant to be displayed to the user. It MUST NOT contain personally identifying information, see
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-user-handle-privacy">§14.6.1 User Handle Contents</a>.
    ///     </para>
    /// </summary>
    public byte[]? UserHandle { get; }

    /// <summary>
    ///     The size of the randomly generated <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-challenge">challenge</a> value.
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-cryptographic-challenges">The minimum allowed size is 16.</a>
    /// </summary>
    public int ChallengeSize { get; }

    /// <summary>
    ///     This OPTIONAL member specifies a time, in milliseconds, that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> is willing to wait for the call to complete. The value is treated as a hint, and MAY be overridden by the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a>.
    /// </summary>
    public uint? Timeout { get; }

    /// <summary>
    ///     <para>Includes parameters of allowed credentials for the authentication ceremony.</para>
    ///     <para>
    ///         This OPTIONAL member is used by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> to find <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticators</a> eligible for this
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremony</a>. It can be used in two ways:
    ///         <list type="bullet">
    ///             <item>
    ///                 <description>
    ///                     <para>
    ///                         If the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> to authenticate is already identified (e.g., if the user has entered a username), then the
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD use this member to list
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-descriptor-for-a-credential-record">credential descriptors for credential records</a> in the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>.
    ///                         This SHOULD usually include all <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">credential records</a> in the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>.
    ///                     </para>
    ///                     <para>
    ///                         The <a href="https://infra.spec.whatwg.org/#list-item">items</a> SHOULD specify <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialdescriptor-transports">transports</a> whenever possible. This helps the
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> optimize the user experience for any given situation. Also note that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> does not
    ///                         need to filter the list when requesting <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a> — the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> will automatically ignore
    ///                         non-eligible credentials if <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialrequestoptions-userverification">userVerification</a> is set to
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-userverificationrequirement-required">required</a>.
    ///                     </para>
    ///                     <para>
    ///                         See also the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-credential-id-privacy-leak">§14.6.3 Privacy leak via credential IDs</a> privacy consideration.
    ///                     </para>
    ///                 </description>
    ///             </item>
    ///             <item>
    ///                 <description>
    ///                     <para>
    ///                         If the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> to authenticate is not already identified, then the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY leave
    ///                         this member <a href="https://infra.spec.whatwg.org/#list-empty">empty</a> or unspecified. In this case, only <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credentials</a> will be utilized in this
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremony</a>, and the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> MAY be identified by the
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorassertionresponse-userhandle">userHandle</a> of the resulting
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticatorassertionresponse">AuthenticatorAssertionResponse</a>. If the available <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticators</a>
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#contains">contain</a> more than one <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credential</a>
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#scope">scoped</a> to the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a>, the credentials are displayed by the
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platform</a> or <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> for the user to select from (see
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticatorGetAssertion-prompt-select-credential">step 7</a> of
    ///                         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-op-get-assertion">§6.3.3 The authenticatorGetAssertion Operation</a>).
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
    ///         This OPTIONAL member specifies the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party's</a> requirements regarding <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-verification">user verification</a> for the
    ///         <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get">get()</a> operation. The value SHOULD be a member of
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-userverificationrequirement">UserVerificationRequirement</a> but <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">client platforms</a> MUST ignore unknown values, treating an
    ///         unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>. Eligible authenticators are filtered to only those capable of satisfying this requirement.
    ///     </para>
    ///     <para>
    ///         See <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-userverificationrequirement">UserVerificationRequirement</a> for the description of
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorselectioncriteria-userverification">userVerification's</a> values and semantics.
    ///     </para>
    /// </summary>
    /// <remarks>defaulting to <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-userverificationrequirement-preferred">"preferred"</a></remarks>
    public UserVerificationRequirement? UserVerification { get; }

    /// <summary>
    ///     This OPTIONAL member contains zero or more elements from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialhints">PublicKeyCredentialHints</a> to guide the user agent in interacting with the user.
    /// </summary>
    /// <remarks>
    ///     defaulting to []
    /// </remarks>
    public PublicKeyCredentialHints[]? Hints { get; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY use this OPTIONAL member to specify a preference regarding <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-conveyance">attestation conveyance</a>. Its
    ///     value SHOULD be a member of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-attestationconveyancepreference">AttestationConveyancePreference</a>. <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">Client platforms</a> MUST ignore
    ///     unknown values, treating an unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    /// </summary>
    /// <remarks>
    ///     defaulting to <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-attestationconveyancepreference-none">"none"</a>
    /// </remarks>
    public AttestationConveyancePreference? Attestation { get; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY use this OPTIONAL member to specify a preference regarding the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation">attestation</a> statement format used
    ///     by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>. Values SHOULD be taken from the <a href="https://www.iana.org/assignments/webauthn/webauthn.xhtml">IANA "WebAuthn Attestation Statement Format Identifiers" registry</a>
    ///     established by <a href="https://www.rfc-editor.org/rfc/rfc8809.html">RFC 8809</a>. Values are ordered from most preferable to least preferable. This parameter is advisory and the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> MAY
    ///     use an attestation statement not enumerated in this parameter.
    /// </summary>
    /// <remarks>
    ///     defaulting to []
    /// </remarks>
    public AttestationStatementFormat[]? AttestationFormats { get; }

    /// <summary>
    ///     <para>
    ///         The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY use this OPTIONAL member to provide <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-extension-input">client extension inputs</a> requesting additional
    ///         processing by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>.
    ///     </para>
    ///     <para>
    ///         The extensions framework is defined in <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-extensions">§9 WebAuthn Extensions</a>. Some extensions are defined in
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-defined-extensions">§10 Defined Extensions</a>; consult the <a href="https://www.iana.org/assignments/webauthn/webauthn.xhtml">IANA "WebAuthn Extension Identifiers" registry</a> established by
    ///         <a href="https://www.rfc-editor.org/rfc/rfc8809.html">RFC 8809</a> for an up-to-date list of registered <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#webauthn-extensions">WebAuthn Extensions</a>.
    ///     </para>
    /// </summary>
    public Dictionary<string, JsonElement>? Extensions { get; }
}
