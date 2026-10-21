using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text.Json;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;

/// <summary>
///     Options for Credential Creation (dictionary PublicKeyCredentialCreationOptions)
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#dictionary-makecredentialoptions">Web Authentication: An API for accessing Public Key Credentials Level 3 - Options for Credential Creation (dictionary PublicKeyCredentialCreationOptions)</a>
/// </remarks>
public class BeginRegistrationCeremonyRequest
{
    /// <summary>
    ///     Constructs <see cref="BeginRegistrationCeremonyRequest" />.
    /// </summary>
    /// <param name="origins">
    ///     Parameters defining acceptable origins for the registration ceremony. If <see langword="null" />, the only acceptable origin is the origin of the current request, computed by
    ///     <see cref="IRelyingPartyOriginProvider" />.
    /// </param>
    /// <param name="topOrigins">
    ///     Parameters defining acceptable topOrigins for the registration ceremony - the origins of the top-level pages within which the Relying Party expects the ceremony to run in an iframe that is not same-origin with its ancestors. If
    ///     <see langword="null" />, the Relying Party doesn't expect to be embedded by other origins: client data with <c>topOrigin</c> is accepted only if <c>topOrigin</c> is equal to <c>origin</c>, and client data with <c>crossOrigin</c> set to
    ///     <see langword="true" /> but without <c>topOrigin</c> is rejected. If specified, client data with <c>crossOrigin</c> set to <see langword="true" /> is accepted, and <c>topOrigin</c>, when present, must be one of these origins.
    /// </param>
    /// <param name="rpDisplayName">A <a href="https://www.w3.org/TR/webauthn-3/#human-palatability">human-palatable</a> identifier for the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a>, intended only for display.</param>
    /// <param name="user">This member contains names and an identifier for the <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a> performing the <a href="https://www.w3.org/TR/webauthn-3/#registration">registration</a>.</param>
    /// <param name="challengeSize">
    ///     The size of the randomly generated <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-challenge">challenge</a> value.
    ///     <a href="https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges">Challenges SHOULD therefore be at least 16 bytes long.</a>
    /// </param>
    /// <param name="pubKeyCredParams">This member specifies the cryptographic signature algorithm with which the newly generated credential will be used, and thus also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.</param>
    /// <param name="timeout">
    ///     This OPTIONAL member specifies a time, in milliseconds, that the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> is willing to wait for the call to complete. This is treated as a hint, and MAY be overridden by the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#client">client</a>.
    /// </param>
    /// <param name="excludeCredentials">Contains the exclusion credentials parameters for the registration ceremony.</param>
    /// <param name="authenticatorSelection">
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> MAY use this OPTIONAL member to specify capabilities and settings that the <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> MUST or
    ///     SHOULD satisfy to participate in the <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-create">create()</a> operation.
    /// </param>
    /// <param name="hints">This OPTIONAL member contains zero or more elements from <a href="https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialhint">PublicKeyCredentialHint</a> to guide the user agent in interacting with the user.</param>
    /// <param name="attestation">
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> MAY use this OPTIONAL member to specify a preference regarding <a href="https://www.w3.org/TR/webauthn-3/#attestation-conveyance">attestation conveyance</a>. Its value
    ///     SHOULD be a member of <a href="https://www.w3.org/TR/webauthn-3/#enumdef-attestationconveyancepreference">AttestationConveyancePreference</a>. <a href="https://www.w3.org/TR/webauthn-3/#client-platform">Client platforms</a> MUST ignore unknown values, treating an unknown
    ///     value as if the <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    /// </param>
    /// <param name="attestationFormats">
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> MAY use this OPTIONAL member to specify a preference regarding the <a href="https://www.w3.org/TR/webauthn-3/#attestation">attestation</a> statement format used by the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a>. Values SHOULD be taken from the
    ///     <a href="https://www.iana.org/assignments/webauthn/webauthn.xhtml#webauthn-attestation-statement-format-ids">IANA "WebAuthn Attestation Statement Format Identifiers"</a> registry established by <a href="https://www.rfc-editor.org/rfc/rfc8809">RFC8809</a>. Values are ordered
    ///     from most preferred to least preferred. Duplicates are allowed but effectively ignored. This parameter is advisory and the <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> MAY use an attestation statement not enumerated in this parameter.
    /// </param>
    /// <param name="extensions">
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> MAY use this OPTIONAL member to provide <a href="https://www.w3.org/TR/webauthn-3/#client-extension-input">client extension inputs</a> requesting additional processing by the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> and <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a>.
    /// </param>
    /// <exception cref="ArgumentException"><paramref name="rpDisplayName" /> is <see langword="null" /> or whitespace string</exception>
    /// <exception cref="ArgumentNullException"><paramref name="user" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException"><paramref name="challengeSize" /> is less than 16</exception>
    /// <exception cref="ArgumentNullException"><paramref name="pubKeyCredParams" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException"><paramref name="pubKeyCredParams" /> is empty</exception>
    /// <exception cref="InvalidEnumArgumentException">One of the elements in the <paramref name="pubKeyCredParams" /> array contains a value not defined in <see cref="CoseAlgorithm" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="excludeCredentials" /> is <see langword="null" /></exception>
    /// <exception cref="InvalidEnumArgumentException">One of the elements in the <paramref name="hints" /> array contains a value not defined in <see cref="PublicKeyCredentialHints" /></exception>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="attestation" /> contains a value that is not defined in <see cref="AttestationConveyancePreference" /></exception>
    /// <exception cref="InvalidEnumArgumentException">One of the elements in the <paramref name="attestationFormats" /> array contains a value not defined in <see cref="AttestationStatementFormat" /></exception>
    public BeginRegistrationCeremonyRequest(
        RegistrationCeremonyOriginParameters? origins,
        RegistrationCeremonyOriginParameters? topOrigins,
        string rpDisplayName,
        PublicKeyCredentialUserEntity user,
        int challengeSize,
        CoseAlgorithm[] pubKeyCredParams,
        uint? timeout,
        RegistrationCeremonyExcludeCredentials excludeCredentials,
        AuthenticatorSelectionCriteria? authenticatorSelection,
        PublicKeyCredentialHints[]? hints,
        AttestationConveyancePreference? attestation,
        AttestationStatementFormat[]? attestationFormats,
        Dictionary<string, JsonElement>? extensions)
    {
        // origins
        Origins = origins;

        // topOrigins
        TopOrigins = topOrigins;

        // rpDisplayName
        if (string.IsNullOrWhiteSpace(rpDisplayName))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(rpDisplayName));
        }

        RpDisplayName = rpDisplayName;

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
        if (pubKeyCredParams.Length == 0)
        {
            throw new ArgumentException($"The {nameof(pubKeyCredParams)} must contain at least one element", nameof(pubKeyCredParams));
        }

        foreach (var algorithm in pubKeyCredParams)
        {
            if (!Enum.IsDefined(algorithm))
            {
                throw new InvalidEnumArgumentException(nameof(pubKeyCredParams), (int) algorithm, typeof(CoseAlgorithm));
            }
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
    ///     Parameters defining acceptable origins for the registration ceremony. If <see langword="null" />, the only acceptable origin is the origin of the current request, computed by <see cref="IRelyingPartyOriginProvider" />.
    /// </summary>
    public RegistrationCeremonyOriginParameters? Origins { get; }

    /// <summary>
    ///     Parameters defining acceptable topOrigins for the registration ceremony - the origins of the top-level pages within which the Relying Party expects the ceremony to run in an iframe that is not same-origin with its ancestors. If
    ///     <see langword="null" />, the Relying Party doesn't expect to be embedded by other origins: client data with <c>topOrigin</c> is accepted only if <c>topOrigin</c> is equal to <c>origin</c>, and client data with <c>crossOrigin</c> set to
    ///     <see langword="true" /> but without <c>topOrigin</c> is rejected. If specified, client data with <c>crossOrigin</c> set to <see langword="true" /> is accepted, and <c>topOrigin</c>, when present, must be one of these origins.
    /// </summary>
    public RegistrationCeremonyOriginParameters? TopOrigins { get; }

    /// <summary>
    ///     A <a href="https://www.w3.org/TR/webauthn-3/#human-palatability">human-palatable</a> identifier for the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a>, intended only for display.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         For example:
    ///         <list type="bullet">
    ///             <item>
    ///                 <description>ACME Corporation</description>
    ///             </item>
    ///             <item>
    ///                 <description>Wonderful Widgets, Inc.</description>
    ///             </item>
    ///             <item>
    ///                 <description>ОАО Примертех</description>
    ///             </item>
    ///         </list>
    ///     </para>
    ///     <para>Authenticators MAY truncate a name member's value so that it fits within 64 bytes, if the authenticator stores the value.</para>
    /// </remarks>
    public string RpDisplayName { get; }

    /// <summary>
    ///     This member contains names and an identifier for the <a href="https://www.w3.org/TR/webauthn-3/#user-account">user account</a> performing the <a href="https://www.w3.org/TR/webauthn-3/#registration">registration</a>.
    /// </summary>
    /// <remarks>
    ///     <a href="https://www.w3.org/TR/webauthn-3/#dictionary-user-credential-params">"User Account Parameters for Credential Generation (dictionary PublicKeyCredentialUserEntity)"</a>
    /// </remarks>
    public PublicKeyCredentialUserEntity User { get; }

    /// <summary>
    ///     The size of the randomly generated <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-challenge">challenge</a> value.
    ///     <a href="https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges">Challenges SHOULD therefore be at least 16 bytes long.</a>
    /// </summary>
    public int ChallengeSize { get; }

    /// <summary>
    ///     This member specifies the cryptographic signature algorithm with which the newly generated credential will be used, and thus also the type of asymmetric key pair to be generated, e.g., RSA or Elliptic Curve.
    /// </summary>
    public CoseAlgorithm[] PubKeyCredParams { get; }

    /// <summary>
    ///     This OPTIONAL member specifies a time, in milliseconds, that the <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> is willing to wait for the call to complete. This is treated as a hint, and MAY be overridden by the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#client">client</a>.
    /// </summary>
    public uint? Timeout { get; }

    /// <summary>
    ///     Contains the exclusion credentials parameters for the registration ceremony.
    /// </summary>
    public RegistrationCeremonyExcludeCredentials ExcludeCredentials { get; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> MAY use this OPTIONAL member to specify capabilities and settings that the <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> MUST or SHOULD satisfy to participate in the
    ///     <a href="https://www.w3.org/TR/credential-management-1/#dom-credentialscontainer-create">create()</a> operation.
    /// </summary>
    public AuthenticatorSelectionCriteria? AuthenticatorSelection { get; }

    /// <summary>
    ///     This OPTIONAL member contains zero or more elements from <a href="https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialhint">PublicKeyCredentialHint</a> to guide the user agent in interacting with the user.
    /// </summary>
    public PublicKeyCredentialHints[]? Hints { get; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> MAY use this OPTIONAL member to specify a preference regarding <a href="https://www.w3.org/TR/webauthn-3/#attestation-conveyance">attestation conveyance</a>. Its value SHOULD be a member of
    ///     <a href="https://www.w3.org/TR/webauthn-3/#enumdef-attestationconveyancepreference">AttestationConveyancePreference</a>. <a href="https://www.w3.org/TR/webauthn-3/#client-platform">Client platforms</a> MUST ignore unknown values, treating an unknown value as if the
    ///     <a href="https://infra.spec.whatwg.org/#map-exists">member does not exist</a>.
    /// </summary>
    /// <remarks>
    ///     defaulting to <a href="https://www.w3.org/TR/webauthn-3/#dom-attestationconveyancepreference-none">"none"</a>
    /// </remarks>
    public AttestationConveyancePreference? Attestation { get; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> MAY use this OPTIONAL member to specify a preference regarding the <a href="https://www.w3.org/TR/webauthn-3/#attestation">attestation</a> statement format used by the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a>. Values SHOULD be taken from the
    ///     <a href="https://www.iana.org/assignments/webauthn/webauthn.xhtml#webauthn-attestation-statement-format-ids">IANA "WebAuthn Attestation Statement Format Identifiers"</a> registry established by <a href="https://www.rfc-editor.org/rfc/rfc8809">RFC8809</a>. Values are ordered
    ///     from most preferred to least preferred. Duplicates are allowed but effectively ignored. This parameter is advisory and the <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a> MAY use an attestation statement not enumerated in this parameter.
    /// </summary>
    /// <remarks>
    ///     defaulting to []
    /// </remarks>
    public AttestationStatementFormat[]? AttestationFormats { get; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/webauthn-3/#relying-party">Relying Party</a> MAY use this OPTIONAL member to provide <a href="https://www.w3.org/TR/webauthn-3/#client-extension-input">client extension inputs</a> requesting additional processing by the
    ///     <a href="https://www.w3.org/TR/webauthn-3/#client">client</a> and <a href="https://www.w3.org/TR/webauthn-3/#authenticator">authenticator</a>.
    /// </summary>
    public Dictionary<string, JsonElement>? Extensions { get; }
}
