using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text.Json;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;

/// <summary>
///     Options for Credential Creation (dictionary PublicKeyCredentialCreationOptions)
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-makecredentialoptions">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.4. Options for Credential Creation (dictionary PublicKeyCredentialCreationOptions)</a>
///     </para>
/// </remarks>
public class PublicKeyCredentialCreationOptions
{
    /// <summary>
    ///     Constructs <see cref="PublicKeyCredentialCreationOptions" />.
    /// </summary>
    /// <param name="rp">This member contains a name and an identifier for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> responsible for the request.</param>
    /// <param name="user">This member contains names and an identifier for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> performing the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration">registration</a>.</param>
    /// <param name="challenge">
    ///     This member specifies a challenge that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> signs, along with other data, when producing an
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-object">attestation object</a> for the newly created credential. See the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-cryptographic-challenges">§13.4.3 Cryptographic Challenges</a>
    ///     security consideration.
    /// </param>
    /// <param name="pubKeyCredParams">
    ///     This member lists the key types and signature algorithms the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> supports, ordered from most preferred to least preferred. The
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> make a best-effort to create a credential of the most preferred type possible. If none of the
    ///     listed types can be created, the <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create">create()</a> operation fails.
    /// </param>
    /// <param name="timeout">
    ///     This OPTIONAL member specifies a time, in milliseconds, that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> is willing to wait for the call to complete. This is treated as a hint, and MAY be overridden by
    ///     the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a>.
    /// </param>
    /// <param name="excludeCredentials">
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD use this OPTIONAL member to list any existing <a href="https://w3c.github.io/webappsec-credential-management/#concept-credential">credentials</a> mapped to this
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> (as identified by <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-user">user</a>.
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-id">id</a>). This ensures that the new credential is not <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#created-on">created on</a> an
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> that already <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#contains">contains</a> a credential mapped to this
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>. If it would be, the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> is requested to instead guide the user to use a different
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>, or return an error if that fails.
    /// </param>
    /// <param name="authenticatorSelection">
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY use this OPTIONAL member to specify capabilities and settings that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> MUST or
    ///     SHOULD satisfy to participate in the <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create">create()</a> operation. See
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-authenticatorSelection">§5.4.4 Authenticator Selection Criteria (dictionary AuthenticatorSelectionCriteria)</a>.
    /// </param>
    /// <param name="hints">This OPTIONAL member contains zero or more elements from <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialhints">PublicKeyCredentialHints</a> to guide the user agent in interacting with the user.</param>
    /// <param name="attestation">
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY use this OPTIONAL member to specify a preference regarding
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-conveyance">attestation conveyance</a>. Its value SHOULD be a member of
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-attestationconveyancepreference">AttestationConveyancePreference</a>. <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-platform">Client platforms</a> MUST ignore unknown values, treating an
    ///     unknown value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    /// </param>
    /// <param name="attestationFormats">
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY use this OPTIONAL member to specify a preference regarding the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation">attestation</a> statement format used
    ///     by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>. Values SHOULD be taken from the <a href="https://www.iana.org/assignments/webauthn/webauthn.xhtml">IANA "WebAuthn Attestation Statement Format Identifiers" registry</a>
    ///     established by <a href="https://www.rfc-editor.org/rfc/rfc8809.html">RFC 8809</a>. Values are ordered from most preferable to least preferable. This parameter is advisory and the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> MAY
    ///     use an attestation statement not enumerated in this parameter.
    /// </param>
    /// <param name="extensions">
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY use this OPTIONAL member to provide <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client-extension-input">client extension inputs</a>
    ///     requesting additional processing by the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="rp" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="user" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="challenge" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException"><paramref name="challenge" /> contains less than 16 bytes</exception>
    /// <exception cref="ArgumentNullException"><paramref name="pubKeyCredParams" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException"><paramref name="pubKeyCredParams" /> is empty</exception>
    /// <exception cref="InvalidEnumArgumentException">One of the elements in the <paramref name="hints" /> array contains a value not defined in <see cref="PublicKeyCredentialHints" /></exception>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="attestation" /> contains a value that is not defined in <see cref="AttestationConveyancePreference" /></exception>
    /// <exception cref="InvalidEnumArgumentException">One of the elements in the <paramref name="attestationFormats" /> array contains a value not defined in <see cref="AttestationStatementFormat" /></exception>
    public PublicKeyCredentialCreationOptions(
        PublicKeyCredentialRpEntity rp,
        PublicKeyCredentialUserEntity user,
        byte[] challenge,
        PublicKeyCredentialParameters[] pubKeyCredParams,
        uint? timeout,
        PublicKeyCredentialDescriptor[]? excludeCredentials,
        AuthenticatorSelectionCriteria? authenticatorSelection,
        PublicKeyCredentialHints[]? hints,
        AttestationConveyancePreference? attestation,
        AttestationStatementFormat[]? attestationFormats,
        Dictionary<string, JsonElement>? extensions)
    {
        // rp
        ArgumentNullException.ThrowIfNull(rp);
        Rp = rp ?? throw new ArgumentNullException(nameof(rp));

        // user
        ArgumentNullException.ThrowIfNull(user);
        User = user;

        // challenge
        ArgumentNullException.ThrowIfNull(challenge);
        // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-cryptographic-challenges
        if (challenge.Length < 16)
        {
            throw new ArgumentException($"The {nameof(challenge)} must be at least 16 bytes long", nameof(challenge));
        }

        Challenge = challenge;

        // pubKeyCredParams
        ArgumentNullException.ThrowIfNull(pubKeyCredParams);
        if (pubKeyCredParams.Length == 0)
        {
            throw new ArgumentException($"The {nameof(pubKeyCredParams)} must contain at least one element", nameof(pubKeyCredParams));
        }

        PubKeyCredParams = pubKeyCredParams;

        // timeout
        Timeout = timeout;

        // excludeCredentials
        ExcludeCredentials = excludeCredentials;

        // authenticatorSelection
        AuthenticatorSelection = authenticatorSelection;

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
    ///     This member contains a name and an identifier for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> responsible for the request.
    /// </summary>
    public PublicKeyCredentialRpEntity Rp { get; }

    /// <summary>
    ///     <para>This member contains names and an identifier for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> performing the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration">registration</a>.</para>
    ///     <para>
    ///         Its value's <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialentity-name">name</a>, <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-displayname">displayName</a> and
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-id">id</a> members are REQUIRED. <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-id">id</a> can be returned as the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorassertionresponse-userhandle">userHandle</a> in some future <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremonies</a>, and is used to
    ///         overwrite existing <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credentials</a> that have the same <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-rp">rp</a>.
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialrpentity-id">id</a> and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-user">user</a>.
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-id">id</a> on the same <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>.
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialentity-name">name</a> and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-displayname">displayName</a> MAY be used by the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> in future
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremonies</a> to help the user select a <a href="https://w3c.github.io/webappsec-credential-management/#concept-credential">credential</a>, but are not returned to the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> as a result of future <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremonies</a>
    ///     </para>
    /// </summary>
    /// <remarks>
    ///     For further details, see <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-pkcredentialentity">§5.4.1 Public Key Entity Description (dictionary PublicKeyCredentialEntity)</a> and
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-user-credential-params">§5.4.3 User Account Parameters for Credential Generation (dictionary PublicKeyCredentialUserEntity)</a>.
    /// </remarks>
    public PublicKeyCredentialUserEntity User { get; }

    /// <summary>
    ///     This member specifies a challenge that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> signs, along with other data, when producing an
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-object">attestation object</a> for the newly created credential. See the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-cryptographic-challenges">§13.4.3 Cryptographic Challenges</a>
    ///     security consideration.
    /// </summary>
    public byte[] Challenge { get; }

    /// <summary>
    ///     This member lists the key types and signature algorithms the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> supports, ordered from most preferred to least preferred. The
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> make a best-effort to create a credential of the most preferred type possible. If none of the
    ///     listed types can be created, the <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create">create()</a> operation fails.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Parties</a> that wish to support a wide range of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticators</a> SHOULD include at least the following
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#typedefdef-cosealgorithmidentifier">COSEAlgorithmIdentifier</a> values:
    ///         <list type="table">
    ///             <listheader>
    ///                 <term>Id</term>
    ///                 <description>Name</description>
    ///             </listheader>
    ///             <item>
    ///                 <term>-8</term>
    ///                 <description>Ed25519 (<a href="https://github.com/dotnet/runtime/issues/63174">not supported</a>)</description>
    ///             </item>
    ///             <item>
    ///                 <term>-7</term>
    ///                 <description>ES256</description>
    ///             </item>
    ///             <item>
    ///                 <term>-257</term>
    ///                 <description>RS256</description>
    ///             </item>
    ///         </list>
    ///     </para>
    ///     <para>Additional signature algorithms can be included as needed.</para>
    /// </remarks>
    public PublicKeyCredentialParameters[] PubKeyCredParams { get; }

    /// <summary>
    ///     This OPTIONAL member specifies a time, in milliseconds, that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> is willing to wait for the call to complete. This is treated as a hint, and MAY be overridden by the
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a>.
    /// </summary>
    public uint? Timeout { get; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> SHOULD use this OPTIONAL member to list any existing <a href="https://w3c.github.io/webappsec-credential-management/#concept-credential">credentials</a> mapped to this
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a> (as identified by <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-user">user</a>.
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-id">id</a>). This ensures that the new credential is not <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#created-on">created on</a> an
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> that already <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#contains">contains</a> a credential mapped to this
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#user-account">user account</a>. If it would be, the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> is requested to instead guide the user to use a different
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>, or return an error if that fails.
    /// </summary>
    /// <remarks>
    ///     defaulting to []
    /// </remarks>
    public PublicKeyCredentialDescriptor[]? ExcludeCredentials { get; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> MAY use this OPTIONAL member to specify capabilities and settings that the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> MUST or
    ///     SHOULD satisfy to participate in the <a href="https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create">create()</a> operation. See
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-authenticatorSelection">§5.4.4 Authenticator Selection Criteria (dictionary AuthenticatorSelectionCriteria)</a>.
    /// </summary>
    public AuthenticatorSelectionCriteria? AuthenticatorSelection { get; }

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
    ///     defaulting to "none"
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
