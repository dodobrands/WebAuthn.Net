using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

/// <summary>
///     authenticatorGetInfo
/// </summary>
/// <remarks>
///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorGetInfo">Client to Authenticator Protocol (CTAP) - authenticatorGetInfo (0x04)</a>
/// </remarks>
// ReSharper disable once InconsistentNaming
[SuppressMessage("ReSharper", "InconsistentNaming")]
[SuppressMessage("Performance", "CA1819:Properties should not return arrays")]
public class AuthenticatorGetInfoJSON
{
    /// <summary>
    ///     Constructs <see cref="AuthenticatorGetInfoJSON" />.
    /// </summary>
    /// <param name="versions">
    ///     List of supported versions. Supported versions are: "FIDO_2_3" for CTAP2.3, "FIDO_2_1" for CTAP2.1, "FIDO_2_0" for CTAP2.0, "FIDO_2_1_PRE" for CTAP2.1 Preview features and "U2F_V2" for CTAP1/U2F authenticators.
    /// </param>
    /// <param name="extensions">List of supported extensions.</param>
    /// <param name="aaguid">
    ///     <para>The claimed AAGUID. 16 bytes in length and encoded the same as MakeCredential AuthenticatorData, as specified in <a href="https://www.w3.org/TR/webauthn-3/#aaguid">WebAuthn</a>.</para>
    ///     <para>
    ///         The FIDO Metadata Statement specification states that all binary values of the authenticatorGetInfo dictionary are base64 encoded, while the FIDO Metadata Service publishes the AAGUID as a hex string (with or without dashes). Both representations are
    ///         supported.
    ///     </para>
    /// </param>
    /// <param name="options">List of supported options.</param>
    /// <param name="maxMsgSize">Maximum message size supported by the authenticator.</param>
    /// <param name="pinUvAuthProtocols">
    ///     List of supported <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#pin-uv-auth-protocol">PIN/UV auth protocols</a> in order of decreasing authenticator preference. MUST NOT contain duplicate values
    ///     nor
    ///     be empty if present.
    /// </param>
    /// <param name="maxCredentialCountInList">
    ///     Maximum number of credentials supported in <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#credentialid">credentialID</a> list at a time by the authenticator. MUST be greater than zero if present.
    /// </param>
    /// <param name="maxCredentialIdLength">Maximum Credential ID Length supported by the authenticator. MUST be greater than zero if present.</param>
    /// <param name="transports">
    ///     List of supported transports. Values are taken from the <a href="https://www.w3.org/TR/webauthn-3/#enumdef-authenticatortransport">AuthenticatorTransport enum in WebAuthn</a>. The list MUST NOT include duplicate values nor be empty if present. Platforms
    ///     MUST tolerate unknown values.
    /// </param>
    /// <param name="algorithms">
    ///     List of supported algorithms for credential generation, as specified in <a href="https://www.w3.org/TR/webauthn-3/#dictionary-credential-params">WebAuthn</a>. The array is ordered from most preferred to least preferred and MUST NOT include duplicate
    ///     entries nor be empty if present. PublicKeyCredentialParameters' algorithm identifiers are values that SHOULD be registered in the <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms registry</a>.
    /// </param>
    /// <param name="maxSerializedLargeBlobArray">
    ///     The maximum size, in bytes, of the <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#serialized-large-blob-array">serialized large-blob array</a> that this authenticator can store. If the
    ///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorLargeBlobs">authenticatorLargeBlobs</a> command is supported, this MUST be specified. Otherwise it MUST NOT be. If specified, the value
    ///     MUST
    ///     be ≥ 1024. Thus, 1024 bytes is the least amount of storage an authenticator must make available for per-credential
    ///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#serialized-large-blob-array">serialized large-blob arrays</a> if it supports the
    ///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorLargeBlobs">large, per-credential blobs</a> feature. This value is not specified and not pertinent if the authenticator implements the
    ///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#sctn-largeBlob-extension">largeBlob extension</a>.
    /// </param>
    /// <param name="forcePinChange">
    ///     If this member is:
    ///     <list type="table">
    ///         <item>
    ///             <term>
    ///                 present and set to <see langword="true" />
    ///             </term>
    ///             <description>
    ///                 <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#getPinToken">getPinToken</a> and
    ///                 <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#getPinUvAuthTokenUsingPinWithPermissions">getPinUvAuthTokenUsingPinWithPermissions</a> will return errors until after a successful
    ///                 <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#changingExistingPin">PIN Change</a>.
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>
    ///                 present and set to <see langword="false" />, or absent
    ///             </term>
    ///             <description>
    ///                 no <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#changingExistingPin">PIN Change</a> is required.
    ///             </description>
    ///         </item>
    ///     </list>
    /// </param>
    /// <param name="minPinLength">
    ///     <para>
    ///         This specifies the current minimum PIN length, in Unicode code points, the authenticator enforces for <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#getinfo-clientpin">ClientPIN</a>. This is
    ///         applicable for ClientPIN only: the <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#getinfo-minpinlength">minPINLength</a> member MUST be absent if the
    ///         <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#getinfo-clientpin">clientPin</a>
    ///         <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#option-id">option ID</a> is absent; it MUST be present if the authenticator supports
    ///         <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorClientPIN">authenticatorClientPIN</a>.
    ///     </para>
    ///     <para>
    ///         The default pre-configured minimum PIN length is at least 4 Unicode code points. Authenticators MAY have a pre-configured default minPINLength of more than 4 code points in certain offerings. On
    ///         <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorReset">reset</a>, minPINLength reverts to its original pre-configured value. Authenticators MAY also have a pre-configured list of
    ///         RP
    ///         IDs authorized to receive the <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#current-minimum-pin-length">current minimum PIN length</a> value via the
    ///         <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#sctn-minpinlength-extension">minPinLength</a> extension.
    ///     </para>
    /// </param>
    /// <param name="firmwareVersion">Indicates the firmware version of the authenticator model identified by AAGUID. Whenever releasing any code change to the authenticator firmware, authenticator MUST increase the version.</param>
    /// <param name="maxCredBlobLength">
    ///     Maximum <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#sctn-credBlob-extension">credBlob</a> length in bytes supported by the authenticator. Must be present if, and only if, credBlob is included
    ///     in
    ///     the supported extensions list. If present, this value MUST be at least 32 bytes.
    /// </param>
    /// <param name="maxRpiDsForSetMinPinLength">
    ///     This specifies the max number of <a href="https://www.w3.org/TR/webauthn-3/#rp-id">RP ID</a> that the authenticator will accept via
    ///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#setMinPINLength">setMinPINLength</a> subcommand. The platform MUST NOT send more than this number of
    ///     <a href="https://www.w3.org/TR/webauthn-3/#rp-id">RP ID</a> to the <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#setMinPINLength">setMinPINLength</a> subcommand. This is in addition to
    ///     pre-configured
    ///     list authenticator may have. If the authenticator does not support adding additional RP IDs, its value is 0. This MUST ONLY be present if, and only if, the authenticator supports the
    ///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#setMinPINLength">setMinPINLength</a> subcommand.
    /// </param>
    /// <param name="preferredPlatformUvAttempts">
    ///     This specifies the preferred number of invocations of the getPinUvAuthTokenUsingUvWithPermissions subCommand the platform may attempt before falling back to the getPinUvAuthTokenUsingPinWithPermissions subCommand or displaying an error. MUST be greater than zero. If the
    ///     value is 1 then all <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#uvretries">uvRetries</a> are internal and the platform MUST only invoke the getPinUvAuthTokenUsingUvWithPermissions subCommand a
    ///     single time. If the value is > 1 the authenticator MUST only decrement <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#uvretries">uvRetries</a> by 1 for each iteration.
    /// </param>
    /// <param name="uvModality">
    ///     This specifies the user verification modality supported by the authenticator via <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorClientPIN">authenticatorClientPIN’s</a>
    ///     getPinUvAuthTokenUsingUvWithPermissions subcommand. This is a hint to help the platform construct user dialogs. The values are defined in
    ///     <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.3-ps-20260105.html#user-verification-methods">FIDO Registry of Predefined Values - "User Verification Methods"</a>. Combining multiple bit-flags from the FIDO Registry of Predefined Values is allowed. If
    ///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#getinfo-clientpin">clientPin</a> is supported it MUST NOT be included in the bit-flags, as clientPIN is not a
    ///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#built-in-user-verification-method">built-in user verification method</a>.
    /// </param>
    /// <param name="certifications">
    ///     This specifies a list of <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#sctn-feature-descriptions-certifications">authenticator certifications</a>.
    /// </param>
    /// <param name="remainingDiscoverableCredentials">
    ///     <para>
    ///         If this member is present it indicates the estimated number of additional <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#discoverable">discoverable</a> credentials that can be stored. If this
    ///         value is zero then platforms SHOULD create non-discoverable credentials if possible.
    ///     </para>
    ///     <para>
    ///         This estimate SHOULD be based on the assumption that all future <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#discoverable">discoverable</a> credentials will have maximally-sized fields and
    ///         SHOULD be zero whenever an attempt to create a <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#discoverable">discoverable</a> credential may fail due to lack of space, even if it’s possible
    ///         that
    ///         some specific request might succeed. For example, a specific request might include fields that are smaller than the maximum possible size and thus succeed, but this value should be zero if a request with maximum-sized fields would fail. Also, a specific request might
    ///         have an <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#makecred-rpid">rp.id</a> and <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-id">user.id</a> that match an
    ///         existing discoverable credential and thus overwrite it, but this value should be set assuming that will not happen.
    ///     </para>
    /// </param>
    /// <param name="vendorPrototypeConfigCommands">
    ///     <para>
    ///         If present the authenticator supports the <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorConfig">authenticatorConfig</a>
    ///         <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#vendorPrototype">vendorPrototype</a> subcommand, and its value is a list of authenticatorConfig vendorCommandId values supported, which MAY be empty.
    ///     </para>
    ///     <para>
    ///         The values are kept as raw JSON values: vendorCommandId is an unsigned 64-bit integer, but some producers of metadata statements serialize it through a double-precision floating-point number
    ///         and emit values outside the uint64 range. The values are validated by <see cref="IFidoMetadataDecoder" />, which ignores the invalid ones instead of rejecting the whole metadata statement.
    ///     </para>
    /// </param>
    /// <param name="attestationFormats">
    ///     <para>List of supported attestation formats. Authenticators that support multiple attestation formats, not counting "none", MUST set this field. Otherwise it is optional.</para>
    ///     <para>
    ///         Values are taken from the <a href="https://www.iana.org/assignments/webauthn/webauthn.xhtml#webauthn-attestation-statement-format-ids">"WebAuthn Attestation Statement Format Identifiers" registry</a> established by
    ///         <a href="https://www.rfc-editor.org/rfc/rfc8809">RFC8809</a>. The list MUST NOT include duplicate values nor be empty if present. Platforms MUST tolerate unknown values. Support for "none" attestation is implied and MUST be omitted.
    ///     </para>
    /// </param>
    /// <param name="uvCountSinceLastPinEntry">
    ///     If present the number of internal User Verification operations since the last pin entry including all failed attempts. This allows the platform to periodically prompt the user for PIN on a biometric device so they don't forget the PIN. This is optional platform behavior
    ///     and the interval is at the discretion of the platform.
    /// </param>
    /// <param name="longTouchForReset">
    ///     If this member is:
    ///     <list type="table">
    ///         <item>
    ///             <term>
    ///                 present and set to <see langword="true" />
    ///             </term>
    ///             <description>the feature is supported and enabled. A touch of &gt;= 5 sec is required for reset.</description>
    ///         </item>
    ///         <item>
    ///             <term>
    ///                 present and set to <see langword="false" />
    ///             </term>
    ///             <description>the feature is supported and disabled.</description>
    ///         </item>
    ///         <item>
    ///             <term>absent</term>
    ///             <description>the feature is unsupported.</description>
    ///         </item>
    ///     </list>
    /// </param>
    /// <param name="encIdentifier">
    ///     <para>
    ///         The value is a byte value containing iv || ct. Where ct is the AES-128-CBC encryption of (128-bit device identifier) using HKDF-SHA-256(salt = 32 zero bytes, IKM =
    ///         <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#puatoken-persistentpinuvauthtoken">persistentPinUvAuthToken</a>, L = 16, info = "encIdentifier"). The encryption iv must be regenerated
    ///         for each output of getInfo.
    ///     </para>
    ///     <para>The value is provided as published in the metadata statement (binary value encoded as a string).</para>
    /// </param>
    /// <param name="transportsForReset">
    ///     List of transports that support the reset command. Values are taken from the <a href="https://www.w3.org/TR/webauthn-3/#enumdef-authenticatortransport">AuthenticatorTransport enum in WebAuthn</a>. The list MUST NOT include duplicate values nor be empty if present.
    ///     Platforms MUST tolerate unknown values.
    /// </param>
    /// <param name="pinComplexityPolicy">
    ///     <para>
    ///         If this member is present and set to <see langword="true" />, the feature is supported and enabled. The authenticator is enforcing an additional current PIN complexity policy beyond minPINLength. If this member is present and set to
    ///         <see langword="false" />, the feature is supported and disabled. If this member is absent, the feature is unsupported.
    ///     </para>
    ///     <para>PIN complexity policies for authenticators are listed in the FIDO MDS. The authenticator may have a pre-configured PIN complexity policy value that is applied after a reset.</para>
    /// </param>
    /// <param name="pinComplexityPolicyUrl">
    ///     <para>If present, a URL that the platform can use to provide the user more information about the enforced PIN policy.</para>
    ///     <para>The value is provided as published in the metadata statement (binary value encoded as a string).</para>
    /// </param>
    /// <param name="maxPinLength">
    ///     <para>
    ///         This specifies the maximum PIN length, in Unicode code points, the authenticator enforces for ClientPIN. An authenticator setting this value still MUST restrict the PIN to be represented in 63 or fewer bytes. This is applicable for ClientPIN only: the maxPINLength member
    ///         MUST be absent if the clientPin option ID is not supported.
    ///     </para>
    ///     <para>
    ///         If the authenticator supports authenticatorClientPIN and the maxPINLength member is absent, the effective default maxPINLength is 63 code points. If specified, the maximum PIN length must be at least 8 Unicode code points. Authenticators MAY have a pre-configured
    ///         default maxPINLength of less than 63 code points in certain offerings.
    ///     </para>
    /// </param>
    /// <param name="encCredStoreState">
    ///     <para>
    ///         The value is a byte value containing iv || ct. Where ct is the AES-128-CBC encryption of (128-bit credential store state) using HKDF-SHA-256(salt = 32 zero bytes, IKM =
    ///         <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#puatoken-persistentpinuvauthtoken">persistentPinUvAuthToken</a>, L = 16, info = "encCredStoreState"). The encryption iv must be
    ///         regenerated for each output of getInfo.
    ///     </para>
    ///     <para>The value is provided as published in the metadata statement (binary value encoded as a string).</para>
    /// </param>
    /// <param name="authenticatorConfigCommands">
    ///     If present the authenticator supports the <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorConfig">authenticatorConfig</a> command, and its value is a list of
    ///     authenticatorConfig subcommand values supported, which MAY be empty.
    /// </param>
    [JsonConstructor]
    public AuthenticatorGetInfoJSON(
        string[] versions,
        string[]? extensions,
        string aaguid,
        Dictionary<string, bool>? options,
        ulong? maxMsgSize,
        ulong[]? pinUvAuthProtocols,
        ulong? maxCredentialCountInList,
        ulong? maxCredentialIdLength,
        string[]? transports,
        FidoPublicKeyCredentialParametersJSON[]? algorithms,
        ulong? maxSerializedLargeBlobArray,
        bool? forcePinChange,
        ulong? minPinLength,
        ulong? firmwareVersion,
        ulong? maxCredBlobLength,
        ulong? maxRpiDsForSetMinPinLength,
        ulong? preferredPlatformUvAttempts,
        ulong? uvModality,
        Dictionary<string, int>? certifications,
        ulong? remainingDiscoverableCredentials,
        JsonElement[]? vendorPrototypeConfigCommands,
        string[]? attestationFormats,
        ulong? uvCountSinceLastPinEntry,
        bool? longTouchForReset,
        string? encIdentifier,
        string[]? transportsForReset,
        bool? pinComplexityPolicy,
        string? pinComplexityPolicyUrl,
        ulong? maxPinLength,
        string? encCredStoreState,
        ulong[]? authenticatorConfigCommands)
    {
        Versions = versions;
        Extensions = extensions;
        Aaguid = aaguid;
        Options = options;
        MaxMsgSize = maxMsgSize;
        PinUvAuthProtocols = pinUvAuthProtocols;
        MaxCredentialCountInList = maxCredentialCountInList;
        MaxCredentialIdLength = maxCredentialIdLength;
        Transports = transports;
        Algorithms = algorithms;
        MaxSerializedLargeBlobArray = maxSerializedLargeBlobArray;
        ForcePINChange = forcePinChange;
        MinPINLength = minPinLength;
        FirmwareVersion = firmwareVersion;
        MaxCredBlobLength = maxCredBlobLength;
        MaxRPIDsForSetMinPINLength = maxRpiDsForSetMinPinLength;
        PreferredPlatformUvAttempts = preferredPlatformUvAttempts;
        UvModality = uvModality;
        Certifications = certifications;
        RemainingDiscoverableCredentials = remainingDiscoverableCredentials;
        VendorPrototypeConfigCommands = vendorPrototypeConfigCommands;
        AttestationFormats = attestationFormats;
        UvCountSinceLastPinEntry = uvCountSinceLastPinEntry;
        LongTouchForReset = longTouchForReset;
        EncIdentifier = encIdentifier;
        TransportsForReset = transportsForReset;
        PinComplexityPolicy = pinComplexityPolicy;
        PinComplexityPolicyURL = pinComplexityPolicyUrl;
        MaxPINLength = maxPinLength;
        EncCredStoreState = encCredStoreState;
        AuthenticatorConfigCommands = authenticatorConfigCommands;
    }

    /// <summary>
    ///     List of supported versions. Supported versions are: "FIDO_2_3" for CTAP2.3, "FIDO_2_1" for CTAP2.1, "FIDO_2_0" for CTAP2.0, "FIDO_2_1_PRE" for CTAP2.1 Preview features and "U2F_V2" for CTAP1/U2F authenticators.
    /// </summary>
    [JsonPropertyName("versions")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string[] Versions { get; }

    /// <summary>
    ///     List of supported extensions.
    /// </summary>
    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string[]? Extensions { get; }

    /// <summary>
    ///     The claimed AAGUID. 16 bytes in length and encoded the same as MakeCredential AuthenticatorData, as specified in <a href="https://www.w3.org/TR/webauthn-3/#aaguid">WebAuthn</a>.
    /// </summary>
    /// <remarks>
    ///     The FIDO Metadata Statement specification states that all binary values of the authenticatorGetInfo dictionary are base64 encoded, while the FIDO Metadata Service publishes the AAGUID as a hex string (with or without dashes). Both representations are supported.
    /// </remarks>
    [JsonPropertyName("aaguid")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Aaguid { get; }

    /// <summary>
    ///     List of supported options.
    /// </summary>
    [JsonPropertyName("options")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public Dictionary<string, bool>? Options { get; }

    /// <summary>
    ///     Maximum message size supported by the authenticator.
    /// </summary>
    [JsonPropertyName("maxMsgSize")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ulong? MaxMsgSize { get; }

    /// <summary>
    ///     List of supported <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#pin-uv-auth-protocol">PIN/UV auth protocols</a> in order of decreasing authenticator preference. MUST NOT contain duplicate values
    ///     nor
    ///     be empty if present.
    /// </summary>
    [JsonPropertyName("pinUvAuthProtocols")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ulong[]? PinUvAuthProtocols { get; }

    /// <summary>
    ///     Maximum number of credentials supported in <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#credentialid">credentialID</a> list at a time by the authenticator. MUST be greater than zero if present.
    /// </summary>
    [JsonPropertyName("maxCredentialCountInList")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ulong? MaxCredentialCountInList { get; }

    /// <summary>
    ///     Maximum Credential ID Length supported by the authenticator. MUST be greater than zero if present.
    /// </summary>
    [JsonPropertyName("maxCredentialIdLength")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ulong? MaxCredentialIdLength { get; }

    /// <summary>
    ///     List of supported transports. Values are taken from the <a href="https://www.w3.org/TR/webauthn-3/#enumdef-authenticatortransport">AuthenticatorTransport enum in WebAuthn</a>. The list MUST NOT include duplicate values nor be empty if present. Platforms MUST tolerate unknown
    ///     values.
    /// </summary>
    [JsonPropertyName("transports")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string[]? Transports { get; }

    /// <summary>
    ///     List of supported algorithms for credential generation, as specified in <a href="https://www.w3.org/TR/webauthn-3/#dictionary-credential-params">WebAuthn</a>. The array is ordered from most preferred to least preferred and MUST NOT include duplicate entries nor be empty if
    ///     present. PublicKeyCredentialParameters' algorithm identifiers are values that SHOULD be registered in the <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms registry</a>.
    /// </summary>
    [JsonPropertyName("algorithms")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public FidoPublicKeyCredentialParametersJSON[]? Algorithms { get; }

    /// <summary>
    ///     The maximum size, in bytes, of the <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#serialized-large-blob-array">serialized large-blob array</a> that this authenticator can store. If the
    ///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorLargeBlobs">authenticatorLargeBlobs</a> command is supported, this MUST be specified. Otherwise it MUST NOT be. If specified, the value
    ///     MUST
    ///     be ≥ 1024. Thus, 1024 bytes is the least amount of storage an authenticator must make available for per-credential
    ///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#serialized-large-blob-array">serialized large-blob arrays</a> if it supports the
    ///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorLargeBlobs">large, per-credential blobs</a> feature. This value is not specified and not pertinent if the authenticator implements the
    ///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#sctn-largeBlob-extension">largeBlob extension</a>.
    /// </summary>
    [JsonPropertyName("maxSerializedLargeBlobArray")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ulong? MaxSerializedLargeBlobArray { get; }

    /// <summary>
    ///     If this member is:
    ///     <list type="table">
    ///         <item>
    ///             <term>
    ///                 present and set to <see langword="true" />
    ///             </term>
    ///             <description>
    ///                 <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#getPinToken">getPinToken</a> and
    ///                 <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#getPinUvAuthTokenUsingPinWithPermissions">getPinUvAuthTokenUsingPinWithPermissions</a> will return errors until after a successful
    ///                 <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#changingExistingPin">PIN Change</a>.
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>
    ///                 present and set to <see langword="false" />, or absent
    ///             </term>
    ///             <description>
    ///                 no <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#changingExistingPin">PIN Change</a> is required.
    ///             </description>
    ///         </item>
    ///     </list>
    /// </summary>
    [JsonPropertyName("forcePINChange")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool? ForcePINChange { get; }

    /// <summary>
    ///     <para>
    ///         This specifies the current minimum PIN length, in Unicode code points, the authenticator enforces for <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#getinfo-clientpin">ClientPIN</a>. This is
    ///         applicable for ClientPIN only: the <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#getinfo-minpinlength">minPINLength</a> member MUST be absent if the
    ///         <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#getinfo-clientpin">clientPin</a>
    ///         <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#option-id">option ID</a> is absent; it MUST be present if the authenticator supports
    ///         <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorClientPIN">authenticatorClientPIN</a>.
    ///     </para>
    ///     <para>
    ///         The default pre-configured minimum PIN length is at least 4 Unicode code points. Authenticators MAY have a pre-configured default minPINLength of more than 4 code points in certain offerings. On
    ///         <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorReset">reset</a>, minPINLength reverts to its original pre-configured value. Authenticators MAY also have a pre-configured list of
    ///         RP
    ///         IDs authorized to receive the <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#current-minimum-pin-length">current minimum PIN length</a> value via the
    ///         <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#sctn-minpinlength-extension">minPinLength</a> extension.
    ///     </para>
    /// </summary>
    [JsonPropertyName("minPINLength")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ulong? MinPINLength { get; }

    /// <summary>
    ///     Indicates the firmware version of the authenticator model identified by AAGUID. Whenever releasing any code change to the authenticator firmware, authenticator MUST increase the version.
    /// </summary>
    [JsonPropertyName("firmwareVersion")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ulong? FirmwareVersion { get; }

    /// <summary>
    ///     Maximum <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#sctn-credBlob-extension">credBlob</a> length in bytes supported by the authenticator. Must be present if, and only if, credBlob is included
    ///     in
    ///     the supported extensions list. If present, this value MUST be at least 32 bytes.
    /// </summary>
    [JsonPropertyName("maxCredBlobLength")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ulong? MaxCredBlobLength { get; }

    /// <summary>
    ///     This specifies the max number of <a href="https://www.w3.org/TR/webauthn-3/#rp-id">RP ID</a> that the authenticator will accept via
    ///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#setMinPINLength">setMinPINLength</a> subcommand. The platform MUST NOT send more than this number of
    ///     <a href="https://www.w3.org/TR/webauthn-3/#rp-id">RP ID</a> to the <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#setMinPINLength">setMinPINLength</a> subcommand. This is in addition to
    ///     pre-configured
    ///     list authenticator may have. If the authenticator does not support adding additional RP IDs, its value is 0. This MUST ONLY be present if, and only if, the authenticator supports the
    ///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#setMinPINLength">setMinPINLength</a> subcommand.
    /// </summary>
    [JsonPropertyName("maxRPIDsForSetMinPINLength")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ulong? MaxRPIDsForSetMinPINLength { get; }

    /// <summary>
    ///     This specifies the preferred number of invocations of the getPinUvAuthTokenUsingUvWithPermissions subCommand the platform may attempt before falling back to the getPinUvAuthTokenUsingPinWithPermissions subCommand or displaying an error. MUST be greater than zero. If the
    ///     value is 1 then all <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#uvretries">uvRetries</a> are internal and the platform MUST only invoke the getPinUvAuthTokenUsingUvWithPermissions subCommand a
    ///     single time. If the value is > 1 the authenticator MUST only decrement <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#uvretries">uvRetries</a> by 1 for each iteration.
    /// </summary>
    [JsonPropertyName("preferredPlatformUvAttempts")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ulong? PreferredPlatformUvAttempts { get; }

    /// <summary>
    ///     This specifies the user verification modality supported by the authenticator via <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorClientPIN">authenticatorClientPIN’s</a>
    ///     getPinUvAuthTokenUsingUvWithPermissions subcommand. This is a hint to help the platform construct user dialogs. The values are defined in
    ///     <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.3-ps-20260105.html#user-verification-methods">FIDO Registry of Predefined Values - "User Verification Methods"</a>. Combining multiple bit-flags from the FIDO Registry of Predefined Values is allowed. If
    ///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#getinfo-clientpin">clientPin</a> is supported it MUST NOT be included in the bit-flags, as clientPIN is not a
    ///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#built-in-user-verification-method">built-in user verification method</a>.
    /// </summary>
    [JsonPropertyName("uvModality")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ulong? UvModality { get; }

    /// <summary>
    ///     This specifies a list of <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#sctn-feature-descriptions-certifications">authenticator certifications</a>.
    /// </summary>
    [JsonPropertyName("certifications")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public Dictionary<string, int>? Certifications { get; }

    /// <summary>
    ///     <para>
    ///         If this member is present it indicates the estimated number of additional <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#discoverable">discoverable</a> credentials that can be stored. If this
    ///         value is zero then platforms SHOULD create non-discoverable credentials if possible.
    ///     </para>
    ///     <para>
    ///         This estimate SHOULD be based on the assumption that all future <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#discoverable">discoverable</a> credentials will have maximally-sized fields and
    ///         SHOULD be zero whenever an attempt to create a <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#discoverable">discoverable</a> credential may fail due to lack of space, even if it’s possible
    ///         that
    ///         some specific request might succeed. For example, a specific request might include fields that are smaller than the maximum possible size and thus succeed, but this value should be zero if a request with maximum-sized fields would fail. Also, a specific request might
    ///         have an <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#makecred-rpid">rp.id</a> and <a href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-id">user.id</a> that match an
    ///         existing discoverable credential and thus overwrite it, but this value should be set assuming that will not happen.
    ///     </para>
    /// </summary>
    [JsonPropertyName("remainingDiscoverableCredentials")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ulong? RemainingDiscoverableCredentials { get; }

    /// <summary>
    ///     <para>
    ///         If present the authenticator supports the <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorConfig">authenticatorConfig</a>
    ///         <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#vendorPrototype">vendorPrototype</a> subcommand, and its value is a list of authenticatorConfig vendorCommandId values supported, which MAY be empty.
    ///     </para>
    ///     <para>
    ///         The values are kept as raw JSON values: vendorCommandId is an unsigned 64-bit integer, but some producers of metadata statements serialize it through a double-precision floating-point number
    ///         and emit values outside the uint64 range. The values are validated by <see cref="IFidoMetadataDecoder" />, which ignores the invalid ones instead of rejecting the whole metadata statement.
    ///     </para>
    /// </summary>
    [JsonPropertyName("vendorPrototypeConfigCommands")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public JsonElement[]? VendorPrototypeConfigCommands { get; }

    /// <summary>
    ///     <para>List of supported attestation formats. Authenticators that support multiple attestation formats, not counting "none", MUST set this field. Otherwise it is optional.</para>
    ///     <para>
    ///         Values are taken from the <a href="https://www.iana.org/assignments/webauthn/webauthn.xhtml#webauthn-attestation-statement-format-ids">"WebAuthn Attestation Statement Format Identifiers" registry</a> established by
    ///         <a href="https://www.rfc-editor.org/rfc/rfc8809">RFC8809</a>. The list MUST NOT include duplicate values nor be empty if present. Platforms MUST tolerate unknown values. Support for "none" attestation is implied and MUST be omitted.
    ///     </para>
    /// </summary>
    [JsonPropertyName("attestationFormats")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string[]? AttestationFormats { get; }

    /// <summary>
    ///     If present the number of internal User Verification operations since the last pin entry including all failed attempts. This allows the platform to periodically prompt the user for PIN on a biometric device so they don't forget the PIN. This is optional platform behavior
    ///     and the interval is at the discretion of the platform.
    /// </summary>
    [JsonPropertyName("uvCountSinceLastPinEntry")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ulong? UvCountSinceLastPinEntry { get; }

    /// <summary>
    ///     If this member is:
    ///     <list type="table">
    ///         <item>
    ///             <term>
    ///                 present and set to <see langword="true" />
    ///             </term>
    ///             <description>the feature is supported and enabled. A touch of &gt;= 5 sec is required for reset.</description>
    ///         </item>
    ///         <item>
    ///             <term>
    ///                 present and set to <see langword="false" />
    ///             </term>
    ///             <description>the feature is supported and disabled.</description>
    ///         </item>
    ///         <item>
    ///             <term>absent</term>
    ///             <description>the feature is unsupported.</description>
    ///         </item>
    ///     </list>
    /// </summary>
    [JsonPropertyName("longTouchForReset")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool? LongTouchForReset { get; }

    /// <summary>
    ///     The value is a byte value containing iv || ct. Where ct is the AES-128-CBC encryption of (128-bit device identifier) using HKDF-SHA-256(salt = 32 zero bytes, IKM =
    ///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#puatoken-persistentpinuvauthtoken">persistentPinUvAuthToken</a>, L = 16, info = "encIdentifier"). The encryption iv must be regenerated for
    ///     each output of getInfo.
    /// </summary>
    /// <remarks>The value is provided as published in the metadata statement (binary value encoded as a string).</remarks>
    [JsonPropertyName("encIdentifier")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? EncIdentifier { get; }

    /// <summary>
    ///     List of transports that support the reset command. Values are taken from the <a href="https://www.w3.org/TR/webauthn-3/#enumdef-authenticatortransport">AuthenticatorTransport enum in WebAuthn</a>. The list MUST NOT include duplicate values nor be empty if present.
    ///     Platforms MUST tolerate unknown values.
    /// </summary>
    [JsonPropertyName("transportsForReset")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string[]? TransportsForReset { get; }

    /// <summary>
    ///     <para>
    ///         If this member is present and set to <see langword="true" />, the feature is supported and enabled. The authenticator is enforcing an additional current PIN complexity policy beyond minPINLength. If this member is present and set to
    ///         <see langword="false" />, the feature is supported and disabled. If this member is absent, the feature is unsupported.
    ///     </para>
    ///     <para>PIN complexity policies for authenticators are listed in the FIDO MDS. The authenticator may have a pre-configured PIN complexity policy value that is applied after a reset.</para>
    /// </summary>
    [JsonPropertyName("pinComplexityPolicy")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool? PinComplexityPolicy { get; }

    /// <summary>
    ///     If present, a URL that the platform can use to provide the user more information about the enforced PIN policy.
    /// </summary>
    /// <remarks>The value is provided as published in the metadata statement (binary value encoded as a string).</remarks>
    [JsonPropertyName("pinComplexityPolicyURL")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? PinComplexityPolicyURL { get; }

    /// <summary>
    ///     <para>
    ///         This specifies the maximum PIN length, in Unicode code points, the authenticator enforces for ClientPIN. An authenticator setting this value still MUST restrict the PIN to be represented in 63 or fewer bytes. This is applicable for ClientPIN only: the maxPINLength member
    ///         MUST be absent if the clientPin option ID is not supported.
    ///     </para>
    ///     <para>
    ///         If the authenticator supports authenticatorClientPIN and the maxPINLength member is absent, the effective default maxPINLength is 63 code points. If specified, the maximum PIN length must be at least 8 Unicode code points. Authenticators MAY have a pre-configured
    ///         default maxPINLength of less than 63 code points in certain offerings.
    ///     </para>
    /// </summary>
    [JsonPropertyName("maxPINLength")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ulong? MaxPINLength { get; }

    /// <summary>
    ///     The value is a byte value containing iv || ct. Where ct is the AES-128-CBC encryption of (128-bit credential store state) using HKDF-SHA-256(salt = 32 zero bytes, IKM =
    ///     <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#puatoken-persistentpinuvauthtoken">persistentPinUvAuthToken</a>, L = 16, info = "encCredStoreState"). The encryption iv must be regenerated
    ///     for each output of getInfo.
    /// </summary>
    /// <remarks>The value is provided as published in the metadata statement (binary value encoded as a string).</remarks>
    [JsonPropertyName("encCredStoreState")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? EncCredStoreState { get; }

    /// <summary>
    ///     If present the authenticator supports the <a href="https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorConfig">authenticatorConfig</a> command, and its value is a list of authenticatorConfig
    ///     subcommand values supported, which MAY be empty.
    /// </summary>
    [JsonPropertyName("authenticatorConfigCommands")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ulong[]? AuthenticatorConfigCommands { get; }
}
