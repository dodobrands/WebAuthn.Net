using System;
using System.ComponentModel;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models;

/// <summary>
///     Options for credential creation.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#dictionary-makecredentialoptions">Web Authentication: An API for accessing Public Key Credentials Level 3 - §5.4. Options for Credential Creation</a>
/// </remarks>
public class BeginCeremonyRequest
{
    /// <summary>
    ///     Constructs <see cref="BeginCeremonyRequest" />.
    /// </summary>
    /// <param name="challengeSize">
    ///     The size of the randomly generated <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-challenge">challenge</a> value.
    ///     <a href="https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges">The minimum allowed size is 16.</a>
    /// </param>
    /// <param name="rp">This member contains data about the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> responsible for the request.</param>
    /// <param name="user">This member contains data about the user account for which the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> is requesting attestation.</param>
    /// <param name="pubKeyCredParams">
    ///     This member contains information about the desired properties of the credential to be created.
    ///     The sequence is ordered from most preferred to least preferred.
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> makes a best-effort to create the most preferred credential that it can.
    /// </param>
    /// <param name="timeout">
    ///     This member specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
    ///     This is treated as a hint, and may be overridden by the <a href="https://www.w3.org/TR/webauthn-3/#client">client</a>.
    /// </param>
    /// <param name="excludeCredentials">
    ///     This member is intended for use by <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a>
    ///     that wish to limit the creation of multiple credentials for the same account on a single authenticator.
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> is requested to return an error
    ///     if the new credential would be created on an authenticator that also contains one of the credentials enumerated in this parameter.
    /// </param>
    /// <param name="authenticatorSelection">
    ///     This member is intended for use by <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a> that wish to select the appropriate authenticators
    ///     to participate in the <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-create">create()</a> operation.
    /// </param>
    /// <param name="attestation">
    ///     This member is intended for use by <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Parties</a> that wish to
    ///     express their preference for <a href="https://www.w3.org/TR/webauthn-3/#attestation-conveyance">attestation conveyance</a>.
    ///     Its values should be members of <see cref="AttestationConveyancePreference" />. Client platforms must ignore unknown values,
    ///     treating an unknown value as if the member does not exist. Its default value is <see cref="AttestationConveyancePreference.None" />.
    /// </param>
    /// <exception cref="ArgumentNullException">If <paramref name="rp" />, <paramref name="user" />, <paramref name="pubKeyCredParams" /> or <paramref name="excludeCredentials" /> is <see langword="null" />.</exception>
    /// <exception cref="ArgumentException">
    ///     If the value of the <paramref name="challengeSize" /> parameter is <a href="https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges">less than 16</a>.
    ///     If <paramref name="pubKeyCredParams" /> contains an empty array or if any of the elements in the <paramref name="pubKeyCredParams" /> array is <see langword="null" />.
    /// </exception>
    /// <exception cref="InvalidEnumArgumentException">If the <paramref name="attestation" /> parameter contains a value not defined in the <see cref="AttestationConveyancePreference" /> enum.</exception>
    /// <summary>
    /// </summary>
    /// <param name="rp"></param>
    /// <param name="user"></param>
    /// <param name="challengeSize"></param>
    /// <param name="pubKeyCredParams"></param>
    /// <param name="timeout"></param>
    /// <param name="excludeCredentials"></param>
    /// <param name="authenticatorSelection"></param>
    /// <param name="hints"></param>
    /// <param name="attestation"></param>
    /// <param name="attestationFormats"></param>
    /// <param name="extensions"></param>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="InvalidEnumArgumentException"></exception>
    // public BeginCeremonyRequest(
    //     PublicKeyCredentialRpEntity rp,
    //     PublicKeyCredentialUserEntity user,
    //     int challengeSize,
    //     PublicKeyCredentialParameters[] pubKeyCredParams,
    //     uint? timeout,
    //     ExcludeCredentialsOptions excludeCredentials,
    //     AuthenticatorSelectionCriteria? authenticatorSelection,
    //     PublicKeyCredentialHints[]? hints,
    //     AttestationConveyancePreference? attestation,
    //     AttestationStatementFormat[]? attestationFormats,
    //     AuthenticationExtensionsClientInputs? extensions)
    // {
    //     ArgumentNullException.ThrowIfNull(rp);
    //     ArgumentNullException.ThrowIfNull(user);
    //     ArgumentNullException.ThrowIfNull(pubKeyCredParams);
    //     ArgumentNullException.ThrowIfNull(excludeCredentials);
    //     if (challengeSize < 16)
    //     {
    //         throw new ArgumentException($"The minimum value of {nameof(challengeSize)} is 16.", nameof(challengeSize));
    //     }
    //
    //     ChallengeSize = challengeSize;
    //     Rp = rp;
    //     User = user;
    //     if (pubKeyCredParams.Length == 0)
    //     {
    //         throw new ArgumentException("Value cannot be an empty collection.", nameof(pubKeyCredParams));
    //     }
    //
    //     // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
    //     if (pubKeyCredParams.Any(static x => x is null))
    //     {
    //         throw new ArgumentException($"One or more objects contained in the {nameof(pubKeyCredParams)} array are equal to null.", nameof(pubKeyCredParams));
    //     }
    //
    //     PubKeyCredParams = pubKeyCredParams;
    //     Timeout = timeout;
    //     ExcludeCredentials = excludeCredentials;
    //     AuthenticatorSelection = authenticatorSelection;
    //     if (attestation.HasValue)
    //     {
    //         if (!Enum.IsDefined(typeof(AttestationConveyancePreference), attestation.Value))
    //         {
    //             throw new InvalidEnumArgumentException(nameof(attestation), (int) attestation.Value, typeof(AttestationConveyancePreference));
    //         }
    //
    //         Attestation = attestation.Value;
    //     }
    // }
    public BeginCeremonyRequest(
        PublicKeyCredentialRpEntity rp,
        PublicKeyCredentialUserEntity user,
        int challengeSize,
        PublicKeyCredentialParameters[] pubKeyCredParams,
        uint? timeout,
        ExcludeCredentialsOptions excludeCredentials,
        AuthenticatorSelectionCriteria? authenticatorSelection,
        PublicKeyCredentialHints[]? hints,
        AttestationConveyancePreference? attestation,
        AttestationStatementFormat[]? attestationFormats,
        AuthenticationExtensionsClientInputs? extensions)
    {
        // rp
        ArgumentNullException.ThrowIfNull(rp);
        Rp = rp;

        // user
        ArgumentNullException.ThrowIfNull(user);
        User = user;

        // challengeSize
        if (challengeSize < 16)
        {
            throw new ArgumentException($"The minimum value of {nameof(challengeSize)} is 16.", nameof(challengeSize));
        }

        ChallengeSize = challengeSize;

        // pubKeyCredParams
        ArgumentNullException.ThrowIfNull(pubKeyCredParams);
        if (pubKeyCredParams.Length < 1)
        {
            throw new ArgumentException($"The {nameof(pubKeyCredParams)} must contain at least one element", nameof(pubKeyCredParams));
        }

        PubKeyCredParams = pubKeyCredParams;

        // timeout
        Timeout = timeout;

        // excludeCredentials
        ArgumentNullException.ThrowIfNull(excludeCredentials);
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
    ///         Its value’s <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialentity-name">name</a>, <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-displayname">displayName</a> and
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-id">id</a> members are REQUIRED. <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-id">id</a> can be returned as the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorassertionresponse-userhandle">userHandle</a> in some future <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremonies</a>, and is used to
    ///         overwrite existing <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#discoverable-credential">discoverable credentials</a> that have the same <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-rp">rp</a>.
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialrpentity-id">id</a> and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-user">user</a>.
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-id">id</a> on the same <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a>.
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialentity-name">name</a> and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialuserentity-displayname">displayName</a> MAY be used by the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authenticator">authenticator</a> and <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#client">client</a> in future
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremonies</a> to help the user select a <a href="https://www.w3.org/TR/credential-management-1/#concept-credential">credential</a>, but are not returned to the
    ///         <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#relying-party">Relying Party</a> as a result of future <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authentication-ceremony">authentication ceremonies</a>
    ///     </para>
    /// </summary>
    /// <remarks>
    ///     For further details, see <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-pkcredentialentity">§5.4.1 Public Key Entity Description (dictionary PublicKeyCredentialEntity)</a> and
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dictionary-user-credential-params">§5.4.3 User Account Parameters for Credential Generation (dictionary PublicKeyCredentialUserEntity)</a>.
    /// </remarks>
    public PublicKeyCredentialUserEntity User { get; }

    /// <summary>
    ///     The size of the randomly generated <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-challenge">challenge</a> value.
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-cryptographic-challenges">The minimum allowed size is 16.</a>
    /// </summary>
    public int ChallengeSize { get; }

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
    ///     Options regulating the exclusion of duplicate user credentials in the same authenticator.
    /// </summary>
    public ExcludeCredentialsOptions ExcludeCredentials { get; }

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
    public AuthenticationExtensionsClientInputs? Extensions { get; }
}
