using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

/// <summary>
///     Metadata Statement
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-keys">FIDO Metadata Statement - §4. Metadata Keys</a>
///     </para>
/// </remarks>
// ReSharper disable once InconsistentNaming
public class MetadataStatementJSON
{
    /// <summary>
    ///     Constructs <see cref="MetadataStatementJSON" />.
    /// </summary>
    /// <param name="legalHeader">The legalHeader, which must be in each Metadata Statement, is an indication of the acceptance of the relevant legal agreement for using the MDS.</param>
    /// <param name="aaid">
    ///     The Authenticator Attestation ID. See <a href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#authenticator-attestation-id-aaid-typedef">[UAFProtocol]</a> for the definition of the AAID structure. This field MUST be set if
    ///     the authenticator implements FIDO UAF.
    /// </param>
    /// <param name="aaguid">
    ///     The Authenticator Attestation GUID. See <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20150904/fido-key-attestation-v2.0-ps-20150904.html#attributes-2">[FIDOKeyAttestation]</a> for the definition of the AAGUID structure. This field MUST be set if the
    ///     authenticator implements FIDO2.
    /// </param>
    /// <param name="attestationCertificateKeyIdentifiers">
    ///     <para>A list of the attestation certificate public key identifiers encoded as hex string.</para>
    ///     <para>
    ///         This value MUST be calculated according to method 1 for computing the keyIdentifier as defined in <a href="https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.2">[RFC5280] section 4.2.1.2</a>. The hex string MUST NOT contain any non-hex characters (e.g. spaces).
    ///         All hex letters MUST be lower case. This field MUST be set if neither aaid nor aaguid are set. Setting this field implies that the attestation certificate(s) are dedicated to a single authenticator model.
    ///     </para>
    ///     <para>All attestationCertificateKeyIdentifier values should be unique within the scope of the Metadata Service.</para>
    /// </param>
    /// <param name="description">
    ///     <para>A human-readable, short description of the authenticator, in English.</para>
    ///     <para>This description MUST be in English, and only contain ASCII <a href="https://tc39.es/ecma262/">[ECMA-262]</a> characters.</para>
    ///     <para>This description SHALL NOT exceed a maximum length of 200 characters.</para>
    /// </param>
    /// <param name="alternativeDescriptions">A list of human-readable short descriptions of the authenticator in different languages.</param>
    /// <param name="authenticatorVersion">
    ///     <para>Earliest (i.e. lowest) trustworthy authenticatorVersion meeting the requirements specified in this metadata statement.</para>
    ///     <para>
    ///         Adding new StatusReport entries with status UPDATE_AVAILABLE to the metadata BLOB object <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html">[FIDOMetadataService]</a> MUST also change this authenticatorVersion if the update fixes
    ///         severe security issues, e.g. the ones reported by preceding StatusReport entries with status code USER_VERIFICATION_BYPASS,ATTESTATION_KEY_COMPROMISE,USER_KEY_REMOTE_COMPROMISE,USER_KEY_PHYSICAL_COMPROMISE,REVOKED.
    ///     </para>
    ///     <para>
    ///         It is RECOMMENDED to assume increased risk if this version is higher (newer) than the firmware version present in an authenticator. For example, if a StatusReport entry with status USER_VERIFICATION_BYPASS or USER_KEY_REMOTE_COMPROMISE precedes the UPDATE_AVAILABLE
    ///         entry, than any firmware version lower (older) than the one specified in the metadata statement is assumed to be vulnerable.
    ///     </para>
    ///     <para>
    ///         The specified version should equal the value of the 'firmwareVersion' member of the authenticatorGetInfo response. If present, see <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html">[FIDOCTAP]</a>.
    ///     </para>
    /// </param>
    /// <param name="protocolFamily">
    ///     <para>The FIDO protocol family. The values "uaf", "u2f", and "fido2" are supported.</para>
    ///     <para>
    ///         Metadata Statements for U2F authenticators MUST set the value of protocolFamily to "u2f". Metadata statement for UAF authenticator MUST set the value of protocolFamily to "uaf", and FIDO2/WebAuthentication Authenticator implementations MUST set the value of
    ///         protocolFamily to "fido2".
    ///     </para>
    /// </param>
    /// <param name="schema">
    ///     <para>The Metadata Schema version</para>
    ///     <para>Metadata schema version defines what schema of the metadata statement is currently present. The schema version of this version of the specification is 3.</para>
    /// </param>
    /// <param name="upv">
    ///     <para>
    ///         The FIDO unified protocol version(s) (related to the specific protocol family) supported by this authenticator. See <a href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html">[UAFProtocol]</a> for the formal definition of
    ///         the Version structure (containing major and minor version numbers).
    ///     </para>
    ///     <para>
    ///         The unified protocol version is determined as follows:
    ///         <list type="bullet">
    ///             <item>
    ///                 <description>in the case of FIDO UAF, use the upv value as specified in the respective "OperationHeader" field, see <a href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html">[UAFProtocol]</a>.</description>
    ///             </item>
    ///             <item>
    ///                 <description>
    ///                     in the case of U2F, use
    ///                     <list type="bullet">
    ///                         <item>
    ///                             <description>major version 1, minor version 0 for U2F v1.0</description>
    ///                         </item>
    ///                         <item>
    ///                             <description>major version 1, minor version 1 for U2F v1.1</description>
    ///                         </item>
    ///                         <item>
    ///                             <description>major version 1, minor version 2 for U2F v1.2 also known as CTAP1</description>
    ///                         </item>
    ///                     </list>
    ///                 </description>
    ///             </item>
    ///             <item>
    ///                 <description>
    ///                     in the case of FIDO2/CTAP2, use
    ///                     <list type="bullet">
    ///                         <item>
    ///                             <description>major version 1, minor version 0 for CTAP 2.0</description>
    ///                         </item>
    ///                         <item>
    ///                             <description>major version 1, minor version 1 for CTAP 2.1</description>
    ///                         </item>
    ///                     </list>
    ///                 </description>
    ///             </item>
    ///         </list>
    ///     </para>
    /// </param>
    /// <param name="authenticationAlgorithms">
    ///     <para>The list of authentication algorithms supported by the authenticator.</para>
    ///     <para>
    ///         Must be set to the complete list of the supported ALG_ constant case-sensitive string names defined in the FIDO Registry of Predefined Values <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html">[FIDORegistry]</a> (section
    ///         "Authentication Algorithms") if the authenticator supports multiple algorithms. E.g. "secp256r1_ecdsa_sha256_raw", "secp256r1_ecdsa_sha256_der".
    ///     </para>
    ///     <para>The list MUST NOT be empty.</para>
    /// </param>
    /// <param name="publicKeyAlgAndEncodings">
    ///     <para>The list of public key formats supported by the authenticator during registration operations.</para>
    ///     <para>
    ///         Must be set to the complete list of the supported ALG_KEY constant case-sensitive string names defined in the FIDO Registry of Predefined Values [FIDORegistry] if the authenticator model supports multiple encodings. See section "Public Key Representation Formats", e.g.
    ///         "ecc_x962_raw", "ecc_x962_der".
    ///     </para>
    ///     <para>
    ///         Because this information is not present in APIs related to authenticator discovery or policy, a FIDO server MUST be prepared to accept and process any and all key representations defined for any public key algorithm it supports. The list MUST NOT be empty. If there are
    ///         multiple values they MUST be ordered by preference.
    ///     </para>
    /// </param>
    /// <param name="attestationTypes">
    ///     Must be set to the complete list of the supported ATTESTATION_ constant case-sensitive string names. See section "Authenticator Attestation Types" of FIDO Registry
    ///     <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html">[FIDORegistry]</a> for all available attestation formats, e.g. "basic_full".
    /// </param>
    /// <param name="userVerificationDetails">
    ///     <para>A list of alternative VerificationMethodANDCombinations.</para>
    ///     <para>userVerificationDetails is a two dimensional array, that informs RP what VerificationMethodANDCombinations user may be required to perform in order to pass user verification, e.g User need to pass fingerprint, or faceprint, or password and palm print, etc.</para>
    ///     <para>
    ///         Consider this userVerificationDetails example:
    ///         <code>
    ///  <![CDATA[
    ///  [
    ///    [
    ///      { "userVerificationMethod": "fingerprint_internal" }
    ///    ],
    ///    // OR
    ///    [
    ///      { "userVerificationMethod": "passcode_internal" }
    ///    ],
    ///    // OR
    ///    [
    ///      { "userVerificationMethod": "faceprint_internal"},
    ///      // AND
    ///      { "userVerificationMethod": "voiceprint_internal"}
    ///    ]
    ///  ]
    ///  ]]>
    ///  </code>
    ///         In this example we have user verification details that describe these potential scenarios: User has an authenticator model that requires
    ///         <list type="bullet">
    ///             <item>
    ///                 <description>Fingerprint, or</description>
    ///             </item>
    ///             <item>
    ///                 <description>Passcode, or</description>
    ///             </item>
    ///             <item>
    ///                 <description>Faceprint and Voiceprint - where Voiceprint and Faceprint must be provided in order to pass user verification.</description>
    ///             </item>
    ///         </list>
    ///     </para>
    ///     <para>
    ///         The RP verifying attestation or assertion, by checking UV flag in the response knows that one of the user verification combinations been passed.
    ///     </para>
    /// </param>
    /// <param name="keyProtection">
    ///     The list of key protection types supported by the authenticator. Must be set to the complete list of the supported KEY_PROTECTION_ constant case-sensitive string names defined in the FIDO Registry of Predefined Values
    ///     <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html">[FIDORegistry]</a> in section "Key Protection Types" e.g. "secure_element". Each value MUST NOT be empty.
    /// </param>
    /// <param name="isKeyRestricted">
    ///     This entry is set to true, if the Uauth private key is restricted by the authenticator to only sign valid FIDO signature assertions. This entry is set to false, if the authenticator doesn't restrict the Uauth key to only sign valid FIDO signature
    ///     assertions. In this case, the calling application could potentially get any hash value signed by the authenticator. If this field is missing, the assumed value is isKeyRestricted=true.
    /// </param>
    /// <param name="isFreshUserVerificationRequired">
    ///     <para>
    ///         This entry is set to true, if Uauth key usage always requires a fresh user verification. If this field is missing, the assumed value is isFreshUserVerificationRequired=true. This entry is set to false, if the Uauth key can be used without requiring a fresh user
    ///         verification, e.g. without any additional user interaction, if the user was verified a (potentially configurable) caching time ago.
    ///     </para>
    ///     <para>In the case of isFreshUserVerificationRequired=false, the FIDO server MUST verify the registration response and/or authentication response and verify that the (maximum) caching time (sometimes also called "authTimeout") is acceptable.</para>
    ///     <para>This entry solely refers to the user verification. In the case of transaction confirmation, the authenticator MUST always ask the user to authorize the specific transaction.</para>
    /// </param>
    /// <param name="matcherProtection">
    ///     The list of matcher protections supported by the authenticator. Must be set to the complete list of the supported MATCHER_PROTECTION constant case-sensitive string names defined in the FIDO Registry of Predefined Values
    ///     <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html">[FIDORegistry]</a>. See section "Matcher Protection Types", e.g. "on_chip". This value MUST NOT be empty.
    /// </param>
    /// <param name="cryptoStrength">
    ///     The authenticator's overall claimed cryptographic strength in bits (sometimes also called security strength or security level). If this value is absent, the cryptographic strength is unknown. If the cryptographic strength of one of the involved
    ///     cryptographic methods is unknown the overall claimed cryptographic strength is also unknown.
    /// </param>
    /// <param name="attachmentHint">
    ///     <para>
    ///         The list of supported attachment hints describing the method(s) by which the authenticator communicates with the FIDO user device. Must be set to the complete list of the supported ATTACHMENT_HINT constant case-sensitive string names defined in the FIDO Registry of
    ///         Predefined Values <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html">[FIDORegistry]</a>. See section "Authenticator Attachment Hints", e.g. "nfc".
    ///     </para>
    ///     <para>This value MUST NOT be empty.</para>
    /// </param>
    /// <param name="tcDisplay">
    ///     <para>
    ///         The list of supported transaction confirmation display capabilities. Must be set to include a valid combination, as specified in FIDO Registry of Predefined Values
    ///         <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html">[FIDORegistry]</a> section "Transaction Confirmation Display Types", of the supported TRANSACTION_CONFIRMATION_DISPLAY constant case-sensitive string names e.g. "any", "hardware".
    ///     </para>
    ///     <para>This value MUST be empty, if transaction confirmation is not supported by the authenticator.</para>
    /// </param>
    /// <param name="tcDisplayContentType">
    ///     <para>Supported MIME content type <a href="https://www.rfc-editor.org/rfc/rfc2049.html">[RFC2049]</a> for the transaction confirmation display, such as text/plain or image/png.</para>
    ///     <para>This value MUST be present if transaction confirmation is supported, i.e. tcDisplay is non-zero.</para>
    /// </param>
    /// <param name="tcDisplayPngCharacteristics">
    ///     <para>A list of alternative DisplayPNGCharacteristicsDescriptor.</para>
    ///     <para>Each of these entries is one alternative of supported image characteristics for displaying a PNG image.</para>
    ///     <para>This list MUST be present if PNG-image based transaction confirmation is supported, i.e. tcDisplay is non-zero and tcDisplayContentType is image/png.</para>
    /// </param>
    /// <param name="attestationRootCertificates">
    ///     <para>
    ///         List of attestation trust anchors for the batch chain in the authenticator attestation. Each element of this array represents a PKIX <a href="https://www.rfc-editor.org/rfc/rfc5280.html">[RFC5280]</a> X.509 certificate that is a valid trust anchor for this
    ///         authenticator model. Multiple certificates might be used for different batches of the same model. The array does not represent a certificate chain, but only the trust anchor of that chain. A trust anchor can be a root certificate, an intermediate CA certificate or even
    ///         the attestation certificate itself.
    ///     </para>
    ///     <para>
    ///         Each array element is a base64-encoded (<a href="https://www.ietf.org/rfc/rfc4648.html#section-4">section 4 of [RFC4648]</a>), DER-encoded <a href="https://www.itu.int/rec/T-REC-X.690-200811-S">[ITU-X690-2008]</a> PKIX certificate value. Each element MUST be dedicated
    ///         for authenticator attestation.
    ///     </para>
    ///     <para>
    ///         Either
    ///         <list type="bullet">
    ///             <item>
    ///                 <description><b>1</b> the manufacturer attestation trust anchor</description>
    ///             </item>
    ///             <item>
    ///                 <description><b>2</b> the trust anchor dedicated to a specific authenticator model</description>
    ///             </item>
    ///         </list>
    ///         MUST be specified.
    ///     </para>
    /// </param>
    /// <param name="ecdaaTrustAnchors">
    ///     A list of trust anchors used for ECDAA attestation. This entry MUST be present if and only if attestationType includes ATTESTATION_ECDAA. The entries in attestationRootCertificates have no relevance for ECDAA attestation. Each ecdaaTrustAnchor
    ///     MUST be dedicated to a single authenticator model (e.g as identified by its AAID/AAGUID).
    /// </param>
    /// <param name="icon">A data: url <a href="https://www.rfc-editor.org/rfc/rfc2397.html">[RFC2397]</a> encoded <a href="https://www.w3.org/TR/png/">[PNG]</a> icon for the Authenticator.</param>
    /// <param name="supportedExtensions">List of extensions supported by the authenticator.</param>
    /// <param name="authenticatorGetInfo">
    ///     <para>Describes supported versions, extensions, AAGUID of the device and its capabilities.</para>
    ///     <para>
    ///         The information is the same reported by an authenticator when invoking the 'authenticatorGetInfo' method, see <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html">[FIDOCTAP]</a>.
    ///     </para>
    /// </param>
    [JsonConstructor]
    public MetadataStatementJSON(
        string? legalHeader,
        string? aaid,
        string? aaguid,
        string[]? attestationCertificateKeyIdentifiers,
        string description,
        Dictionary<string, string>? alternativeDescriptions,
        ulong authenticatorVersion,
        string protocolFamily,
        ushort schema,
        VersionJSON[] upv,
        string[] authenticationAlgorithms,
        string[] publicKeyAlgAndEncodings,
        string[] attestationTypes,
        VerificationMethodDescriptorJSON[][] userVerificationDetails,
        string[] keyProtection,
        bool? isKeyRestricted,
        bool? isFreshUserVerificationRequired,
        string[] matcherProtection,
        ushort? cryptoStrength,
        string[]? attachmentHint,
        string[] tcDisplay,
        string? tcDisplayContentType,
        DisplayPNGCharacteristicsDescriptorJSON[]? tcDisplayPngCharacteristics,
        string[] attestationRootCertificates,
        EcdaaTrustAnchorJSON[]? ecdaaTrustAnchors,
        string? icon,
        ExtensionDescriptorJSON[]? supportedExtensions,
        AuthenticatorGetInfoJSON? authenticatorGetInfo)
    {
        LegalHeader = legalHeader;
        Aaid = aaid;
        Aaguid = aaguid;
        AttestationCertificateKeyIdentifiers = attestationCertificateKeyIdentifiers;
        Description = description;
        AlternativeDescriptions = alternativeDescriptions;
        AuthenticatorVersion = authenticatorVersion;
        ProtocolFamily = protocolFamily;
        Schema = schema;
        Upv = upv;
        AuthenticationAlgorithms = authenticationAlgorithms;
        PublicKeyAlgAndEncodings = publicKeyAlgAndEncodings;
        AttestationTypes = attestationTypes;
        UserVerificationDetails = userVerificationDetails;
        KeyProtection = keyProtection;
        IsKeyRestricted = isKeyRestricted;
        IsFreshUserVerificationRequired = isFreshUserVerificationRequired;
        MatcherProtection = matcherProtection;
        CryptoStrength = cryptoStrength;
        AttachmentHint = attachmentHint;
        TcDisplay = tcDisplay;
        TcDisplayContentType = tcDisplayContentType;
        TcDisplayPNGCharacteristics = tcDisplayPngCharacteristics;
        AttestationRootCertificates = attestationRootCertificates;
        EcdaaTrustAnchors = ecdaaTrustAnchors;
        Icon = icon;
        SupportedExtensions = supportedExtensions;
        AuthenticatorGetInfo = authenticatorGetInfo;
    }

    /// <summary>
    ///     The legalHeader, which must be in each Metadata Statement, is an indication of the acceptance of the relevant legal agreement for using the MDS.
    /// </summary>
    /// <remarks>
    ///     <para>The example of a Metadata Statement legal header is:</para>
    ///     <para>"legalHeader": "https://fidoalliance.org/metadata/metadata-statement-legal-header/".</para>
    /// </remarks>
    [JsonPropertyName("legalHeader")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? LegalHeader { get; }

    /// <summary>
    ///     The Authenticator Attestation ID. See <a href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#authenticator-attestation-id-aaid-typedef">[UAFProtocol]</a> for the definition of the AAID structure. This field MUST be set if
    ///     the authenticator implements FIDO UAF.
    /// </summary>
    /// <remarks>
    ///     FIDO UAF Authenticators support AAID, but they don't support AAGUID. It is always expected that the UAF Authenticator (or at least the UAF ASM) knows and provides the correct AAID.
    /// </remarks>
    [JsonPropertyName("aaid")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? Aaid { get; }

    /// <summary>
    ///     The Authenticator Attestation GUID. See <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20150904/fido-key-attestation-v2.0-ps-20150904.html#attributes-2">[FIDOKeyAttestation]</a> for the definition of the AAGUID structure. This field MUST be set if the authenticator
    ///     implements FIDO2.
    /// </summary>
    /// <remarks>
    ///     FIDO 2 Authenticators support AAGUID, but they don't support AAID.
    /// </remarks>
    [JsonPropertyName("aaguid")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? Aaguid { get; }

    /// <summary>
    ///     <para>A list of the attestation certificate public key identifiers encoded as hex string.</para>
    ///     <para>
    ///         This value MUST be calculated according to method 1 for computing the keyIdentifier as defined in <a href="https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.2">[RFC5280] section 4.2.1.2</a>. The hex string MUST NOT contain any non-hex characters (e.g. spaces).
    ///         All hex letters MUST be lower case. This field MUST be set if neither aaid nor aaguid are set. Setting this field implies that the attestation certificate(s) are dedicated to a single authenticator model.
    ///     </para>
    ///     <para>All attestationCertificateKeyIdentifier values should be unique within the scope of the Metadata Service.</para>
    /// </summary>
    /// <remarks>FIDO U2F Authenticators typically do not support AAID nor AAGUID, but they use attestation certificates dedicated to a single authenticator model.</remarks>
    [JsonPropertyName("attestationCertificateKeyIdentifiers")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string[]? AttestationCertificateKeyIdentifiers { get; }

    /// <summary>
    ///     <para>A human-readable, short description of the authenticator, in English.</para>
    ///     <para>This description MUST be in English, and only contain ASCII <a href="https://tc39.es/ecma262/">[ECMA-262]</a> characters.</para>
    ///     <para>This description SHALL NOT exceed a maximum length of 200 characters.</para>
    /// </summary>
    /// <remarks>
    ///     This description should help an administrator configuring authenticator policies. This description might deviate from the description returned by the ASM for that authenticator. This description should contain the public authenticator trade name and the publicly known vendor
    ///     name.
    /// </remarks>
    [JsonPropertyName("description")]
    [Required]
    [MaxLength(200)]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Description { get; }

    /// <summary>
    ///     A list of human-readable short descriptions of the authenticator in different languages.
    /// </summary>
    [JsonPropertyName("alternativeDescriptions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public Dictionary<string, string>? AlternativeDescriptions { get; }

    /// <summary>
    ///     <para>Earliest (i.e. lowest) trustworthy authenticatorVersion meeting the requirements specified in this metadata statement.</para>
    ///     <para>
    ///         Adding new StatusReport entries with status UPDATE_AVAILABLE to the metadata BLOB object <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html">[FIDOMetadataService]</a> MUST also change this authenticatorVersion if the update fixes
    ///         severe security issues, e.g. the ones reported by preceding StatusReport entries with status code USER_VERIFICATION_BYPASS,ATTESTATION_KEY_COMPROMISE,USER_KEY_REMOTE_COMPROMISE,USER_KEY_PHYSICAL_COMPROMISE,REVOKED.
    ///     </para>
    ///     <para>
    ///         It is RECOMMENDED to assume increased risk if this version is higher (newer) than the firmware version present in an authenticator. For example, if a StatusReport entry with status USER_VERIFICATION_BYPASS or USER_KEY_REMOTE_COMPROMISE precedes the UPDATE_AVAILABLE
    ///         entry, than any firmware version lower (older) than the one specified in the metadata statement is assumed to be vulnerable.
    ///     </para>
    ///     <para>
    ///         The specified version should equal the value of the 'firmwareVersion' member of the authenticatorGetInfo response. If present, see <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html">[FIDOCTAP]</a>.
    ///     </para>
    /// </summary>
    [JsonPropertyName("authenticatorVersion")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public ulong AuthenticatorVersion { get; }

    /// <summary>
    ///     <para>The FIDO protocol family. The values "uaf", "u2f", and "fido2" are supported.</para>
    ///     <para>
    ///         Metadata Statements for U2F authenticators MUST set the value of protocolFamily to "u2f". Metadata statement for UAF authenticator MUST set the value of protocolFamily to "uaf", and FIDO2/WebAuthentication Authenticator implementations MUST set the value of
    ///         protocolFamily to "fido2".
    ///     </para>
    /// </summary>
    [JsonPropertyName("protocolFamily")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string ProtocolFamily { get; }

    /// <summary>
    ///     <para>The Metadata Schema version</para>
    ///     <para>Metadata schema version defines what schema of the metadata statement is currently present. The schema version of this version of the specification is 3.</para>
    /// </summary>
    [JsonPropertyName("schema")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public ushort Schema { get; }

    /// <summary>
    ///     <para>
    ///         The FIDO unified protocol version(s) (related to the specific protocol family) supported by this authenticator. See <a href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html">[UAFProtocol]</a> for the formal definition of
    ///         the Version structure (containing major and minor version numbers).
    ///     </para>
    ///     <para>
    ///         The unified protocol version is determined as follows:
    ///         <list type="bullet">
    ///             <item>
    ///                 <description>in the case of FIDO UAF, use the upv value as specified in the respective "OperationHeader" field, see <a href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html">[UAFProtocol]</a>.</description>
    ///             </item>
    ///             <item>
    ///                 <description>
    ///                     in the case of U2F, use
    ///                     <list type="bullet">
    ///                         <item>
    ///                             <description>major version 1, minor version 0 for U2F v1.0</description>
    ///                         </item>
    ///                         <item>
    ///                             <description>major version 1, minor version 1 for U2F v1.1</description>
    ///                         </item>
    ///                         <item>
    ///                             <description>major version 1, minor version 2 for U2F v1.2 also known as CTAP1</description>
    ///                         </item>
    ///                     </list>
    ///                 </description>
    ///             </item>
    ///             <item>
    ///                 <description>
    ///                     in the case of FIDO2/CTAP2, use
    ///                     <list type="bullet">
    ///                         <item>
    ///                             <description>major version 1, minor version 0 for CTAP 2.0</description>
    ///                         </item>
    ///                         <item>
    ///                             <description>major version 1, minor version 1 for CTAP 2.1</description>
    ///                         </item>
    ///                     </list>
    ///                 </description>
    ///             </item>
    ///         </list>
    ///     </para>
    /// </summary>
    [JsonPropertyName("upv")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public VersionJSON[] Upv { get; }

    /// <summary>
    ///     <para>The list of authentication algorithms supported by the authenticator.</para>
    ///     <para>
    ///         Must be set to the complete list of the supported ALG_ constant case-sensitive string names defined in the FIDO Registry of Predefined Values
    ///         <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#authentication-algorithms">[FIDORegistry] (section "Authentication Algorithms")</a> if the authenticator supports multiple algorithms. E.g. "secp256r1_ecdsa_sha256_raw",
    ///         "secp256r1_ecdsa_sha256_der".
    ///     </para>
    ///     <para>The list MUST NOT be empty.</para>
    /// </summary>
    /// <remarks>
    ///     <list type="bullet">
    ///         <item>
    ///             <term>
    ///                 <b>FIDO UAF Authenticators</b>
    ///             </term>
    ///             <description>
    ///                 For verification purposes, the field SignatureAlgAndEncoding in the FIDO UAF authentication assertion <a href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-authnr-cmds-v1.2-ps-20201020.html">[UAFAuthnrCommands]</a> should be used to determine
    ///                 the actual signature algorithm and encoding.
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>
    ///                 <b>FIDO U2F Authenticators</b>
    ///             </term>
    ///             <description>
    ///                 FIDO U2F only supports one signature algorithm and encoding: ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html">[FIDORegistry]</a>.
    ///             </description>
    ///         </item>
    ///     </list>
    /// </remarks>
    [JsonPropertyName("authenticationAlgorithms")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string[] AuthenticationAlgorithms { get; }

    /// <summary>
    ///     <para>The list of public key formats supported by the authenticator during registration operations.</para>
    ///     <para>
    ///         Must be set to the complete list of the supported ALG_KEY constant case-sensitive string names defined in the FIDO Registry of Predefined Values [FIDORegistry] if the authenticator model supports multiple encodings. See section "Public Key Representation Formats", e.g.
    ///         "ecc_x962_raw", "ecc_x962_der".
    ///     </para>
    ///     <para>
    ///         Because this information is not present in APIs related to authenticator discovery or policy, a FIDO server MUST be prepared to accept and process any and all key representations defined for any public key algorithm it supports. The list MUST NOT be empty. If there are
    ///         multiple values they MUST be ordered by preference.
    ///     </para>
    /// </summary>
    /// <remarks>
    ///     <list type="bullet">
    ///         <item>
    ///             <term>
    ///                 <b>FIDO UAF Authenticators</b>
    ///             </term>
    ///             <description>
    ///                 For verification purposes, the field PublicKeyAlgAndEncoding in the FIDO UAF registration assertion <a href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-authnr-cmds-v1.2-ps-20201020.html">[UAFAuthnrCommands]</a> should be used to determine
    ///                 the actual encoding of the public key.
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <term>
    ///                 <b>FIDO U2F Authenticators</b>
    ///             </term>
    ///             <description>
    ///                 FIDO U2F only supports one public key encoding: ALG_KEY_ECC_X962_RAW <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html">[FIDORegistry]</a>.
    ///             </description>
    ///         </item>
    ///     </list>
    /// </remarks>
    [JsonPropertyName("publicKeyAlgAndEncodings")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string[] PublicKeyAlgAndEncodings { get; }

    /// <summary>
    ///     Must be set to the complete list of the supported ATTESTATION_ constant case-sensitive string names. See section "Authenticator Attestation Types" of FIDO Registry <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html">[FIDORegistry]</a>
    ///     for all available attestation formats, e.g. "basic_full".
    /// </summary>
    [JsonPropertyName("attestationTypes")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string[] AttestationTypes { get; }

    /// <summary>
    ///     <para>A list of alternative VerificationMethodANDCombinations.</para>
    ///     <para>userVerificationDetails is a two dimensional array, that informs RP what VerificationMethodANDCombinations user may be required to perform in order to pass user verification, e.g User need to pass fingerprint, or faceprint, or password and palm print, etc.</para>
    ///     <para>
    ///         Consider this userVerificationDetails example:
    ///         <code>
    /// <![CDATA[
    /// [
    ///   [
    ///     { "userVerificationMethod": "fingerprint_internal" }
    ///   ],
    ///   // OR
    ///   [
    ///     { "userVerificationMethod": "passcode_internal" }
    ///   ],
    ///   // OR
    ///   [
    ///     { "userVerificationMethod": "faceprint_internal"},
    ///     // AND
    ///     { "userVerificationMethod": "voiceprint_internal"}
    ///   ]
    /// ]
    /// ]]>
    /// </code>
    ///         In this example we have user verification details that describe these potential scenarios: User has an authenticator model that requires
    ///         <list type="bullet">
    ///             <item>
    ///                 <description>Fingerprint, or</description>
    ///             </item>
    ///             <item>
    ///                 <description>Passcode, or</description>
    ///             </item>
    ///             <item>
    ///                 <description>Faceprint and Voiceprint - where Voiceprint and Faceprint must be provided in order to pass user verification.</description>
    ///             </item>
    ///         </list>
    ///     </para>
    ///     <para>
    ///         The RP verifying attestation or assertion, by checking UV flag in the response knows that one of the user verification combinations been passed.
    ///     </para>
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         FIDO2 "Security Keys" will typically support "none", or "presence_internal", or "passcode_external" <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html">[FIDOCTAP]</a>
    ///     </para>
    ///     <para>The FIDO Client will typically prevent "none" (silent authentication) and "passcode_external" (without "presence_internal") from being used in practice</para>
    /// </remarks>
    [JsonPropertyName("userVerificationDetails")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public VerificationMethodDescriptorJSON[][] UserVerificationDetails { get; }

    /// <summary>
    ///     The list of key protection types supported by the authenticator. Must be set to the complete list of the supported KEY_PROTECTION_ constant case-sensitive string names defined in the FIDO Registry of Predefined Values
    ///     <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html">[FIDORegistry]</a> in section "Key Protection Types" e.g. "secure_element". Each value MUST NOT be empty.
    /// </summary>
    /// <remarks>
    ///     The keyProtection specified here denotes the effective security of the attestation key and Uauth private key and the effective trustworthiness of the attested attributes in the "sign assertion". Effective security means that key extraction or injecting malicious attested
    ///     attributes is only possible if the specified protection method is compromised. For example, if keyProtection=TEE is stated, it shall be impossible to extract the attestation key or the Uauth private key or to inject any malicious attested attributes without breaking the TEE.
    /// </remarks>
    [JsonPropertyName("keyProtection")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string[] KeyProtection { get; }

    /// <summary>
    ///     This entry is set to true, if the Uauth private key is restricted by the authenticator to only sign valid FIDO signature assertions. This entry is set to false, if the authenticator doesn't restrict the Uauth key to only sign valid FIDO signature assertions. In this case,
    ///     the calling application could potentially get any hash value signed by the authenticator. If this field is missing, the assumed value is isKeyRestricted=true.
    /// </summary>
    /// <remarks>
    ///     Only in the case of isKeyRestricted=true, the FIDO server can trust a signature counter, transaction text, or any other extension in the signature assertion to have been correctly processed/controlled by the authenticator.
    /// </remarks>
    [JsonPropertyName("isKeyRestricted")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool? IsKeyRestricted { get; }

    /// <summary>
    ///     <para>
    ///         This entry is set to true, if Uauth key usage always requires a fresh user verification. If this field is missing, the assumed value is isFreshUserVerificationRequired=true. This entry is set to false, if the Uauth key can be used without requiring a fresh user
    ///         verification, e.g. without any additional user interaction, if the user was verified a (potentially configurable) caching time ago.
    ///     </para>
    ///     <para>In the case of isFreshUserVerificationRequired=false, the FIDO server MUST verify the registration response and/or authentication response and verify that the (maximum) caching time (sometimes also called "authTimeout") is acceptable.</para>
    ///     <para>This entry solely refers to the user verification. In the case of transaction confirmation, the authenticator MUST always ask the user to authorize the specific transaction.</para>
    /// </summary>
    /// <remarks>
    ///     Note that in the case of isFreshUserVerificationRequired=false, the calling App could trigger use of the key without user involvement. In this case it is the responsibility of the App to ask for user consent.
    /// </remarks>
    [JsonPropertyName("isFreshUserVerificationRequired")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool? IsFreshUserVerificationRequired { get; }

    /// <summary>
    ///     The list of matcher protections supported by the authenticator. Must be set to the complete list of the supported MATCHER_PROTECTION constant case-sensitive string names defined in the FIDO Registry of Predefined Values
    ///     <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html">[FIDORegistry]</a>. See section "Matcher Protection Types", e.g. "on_chip". This value MUST NOT be empty.
    /// </summary>
    /// <remarks>
    ///     <para>If multiple user verification methods ("matchers") are implemented, then this value must reflect the weakest implementation of all user verification methods.</para>
    ///     <para>If a user verification method implementation is split across multiple components, then this value must reflect the weakest implementation of all those components.</para>
    ///     <para>
    ///         The matcherProtection specified here denotes the effective security of the FIDO authenticator's user verification. This means that a false positive user verification implies breach of the stated method. For example, if matcherProtection=TEE is stated, it shall be
    ///         impossible to trigger use of the Uauth private key when bypassing the user verification without breaking the TEE.
    ///     </para>
    /// </remarks>
    [JsonPropertyName("matcherProtection")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string[] MatcherProtection { get; }

    /// <summary>
    ///     The authenticator's overall claimed cryptographic strength in bits (sometimes also called security strength or security level). If this value is absent, the cryptographic strength is unknown. If the cryptographic strength of one of the involved cryptographic methods is
    ///     unknown the overall claimed cryptographic strength is also unknown.
    /// </summary>
    /// <remarks>
    ///     See
    ///     <a href="https://fidoalliance.org/specs/fido-security-requirements/fido-authenticator-security-requirements-v1.4-fd-20201102.html#dfn-overall-claimed-cryptographic-strength">[FIDOAuthenticatorSecurityRequirements], requirement 2.1.4, "Overall Claimed Cryptographic Strength"</a>
    /// </remarks>
    [JsonPropertyName("cryptoStrength")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ushort? CryptoStrength { get; }

    /// <summary>
    ///     <para>
    ///         The list of supported attachment hints describing the method(s) by which the authenticator communicates with the FIDO user device. Must be set to the complete list of the supported ATTACHMENT_HINT constant case-sensitive string names defined in the FIDO Registry of
    ///         Predefined Values <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html">[FIDORegistry]</a>. See section "Authenticator Attachment Hints", e.g. "nfc".
    ///     </para>
    ///     <para>This value MUST NOT be empty.</para>
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         The connection state and topology of an authenticator may be transient and cannot be relied on as authoritative by a relying party, but the metadata field should have all the bit flags set for the topologies possible for the authenticator. For example, an authenticator
    ///         instantiated as a single-purpose hardware token that can communicate over bluetooth should set ATTACHMENT_HINT_EXTERNAL but not ATTACHMENT_HINT_INTERNAL.
    ///     </para>
    ///     <para>For FIDO2 the values of attachmentHint MUST correspond to the authenticatorGetInfo.transports if present.</para>
    ///     <para>
    ///         See the field authenticatorGetInfo for FIDO2 authenticators; which expose similar information in the 'transports' member when invoking the 'authenticatorGetInfo' method. See
    ///         <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html">[FIDOCTAP]</a>
    ///     </para>
    /// </remarks>
    [JsonPropertyName("attachmentHint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string[]? AttachmentHint { get; }

    /// <summary>
    ///     <para>
    ///         The list of supported transaction confirmation display capabilities. Must be set to include a valid combination, as specified in FIDO Registry of Predefined Values
    ///         <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html">[FIDORegistry]</a> section "Transaction Confirmation Display Types", of the supported TRANSACTION_CONFIRMATION_DISPLAY constant case-sensitive string names e.g. "any", "hardware".
    ///     </para>
    ///     <para>This value MUST be empty, if transaction confirmation is not supported by the authenticator.</para>
    /// </summary>
    /// <remarks>
    ///     The tcDisplay specified here denotes the effective security of the authenticator's transaction confirmation display. This means that only a breach of the stated method allows an attacker to inject transaction text to be included in the signature assertion which hasn't been
    ///     displayed and confirmed by the user.
    /// </remarks>
    [JsonPropertyName("tcDisplay")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string[] TcDisplay { get; }

    /// <summary>
    ///     <para>Supported MIME content type <a href="https://www.rfc-editor.org/rfc/rfc2049.html">[RFC2049]</a> for the transaction confirmation display, such as text/plain or image/png.</para>
    ///     <para>This value MUST be present if transaction confirmation is supported, i.e. tcDisplay is non-zero.</para>
    /// </summary>
    [JsonPropertyName("tcDisplayContentType")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? TcDisplayContentType { get; }

    /// <summary>
    ///     <para>A list of alternative DisplayPNGCharacteristicsDescriptor.</para>
    ///     <para>Each of these entries is one alternative of supported image characteristics for displaying a PNG image.</para>
    ///     <para>This list MUST be present if PNG-image based transaction confirmation is supported, i.e. tcDisplay is non-zero and tcDisplayContentType is image/png.</para>
    /// </summary>
    [JsonPropertyName("tcDisplayPNGCharacteristics")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public DisplayPNGCharacteristicsDescriptorJSON[]? TcDisplayPNGCharacteristics { get; }

    /// <summary>
    ///     <para>
    ///         List of attestation trust anchors for the batch chain in the authenticator attestation. Each element of this array represents a PKIX <a href="https://www.rfc-editor.org/rfc/rfc5280.html">[RFC5280]</a> X.509 certificate that is a valid trust anchor for this
    ///         authenticator model. Multiple certificates might be used for different batches of the same model. The array does not represent a certificate chain, but only the trust anchor of that chain. A trust anchor can be a root certificate, an intermediate CA certificate or even
    ///         the attestation certificate itself.
    ///     </para>
    ///     <para>
    ///         Each array element is a base64-encoded (<a href="https://www.ietf.org/rfc/rfc4648.html#section-4">section 4 of [RFC4648]</a>), DER-encoded <a href="https://www.itu.int/rec/T-REC-X.690-200811-S">[ITU-X690-2008]</a> PKIX certificate value. Each element MUST be dedicated
    ///         for authenticator attestation.
    ///     </para>
    ///     <para>
    ///         Either
    ///         <list type="bullet">
    ///             <item>
    ///                 <description><b>1</b> the manufacturer attestation trust anchor</description>
    ///             </item>
    ///             <item>
    ///                 <description><b>2</b> the trust anchor dedicated to a specific authenticator model</description>
    ///             </item>
    ///         </list>
    ///         MUST be specified.
    ///     </para>
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         A certificate listed here is a trust anchor. It might (1) be the actual certificate presented by the authenticator, or it might (2) be an issuing authority certificate from the vendor that the attestation certificate chains to. In the case of (1), a binary comparison
    ///         is sufficient to determine if the attestation trust anchor is the attestation certificate itself.
    ///     </para>
    ///     <para>
    ///         In the case of "uaf" protocol family, the attestation certificate itself and the ordered certificate chain are included in the registration assertion (see
    ///         <a href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-authnr-cmds-v1.2-ps-20201020.html">[UAFAuthnrCommands]</a>).
    ///     </para>
    /// </remarks>
    [JsonPropertyName("attestationRootCertificates")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string[] AttestationRootCertificates { get; }

    /// <summary>
    ///     A list of trust anchors used for ECDAA attestation. This entry MUST be present if and only if attestationType includes ATTESTATION_ECDAA. The entries in attestationRootCertificates have no relevance for ECDAA attestation. Each ecdaaTrustAnchor MUST be dedicated to a single
    ///     authenticator model (e.g as identified by its AAID/AAGUID).
    /// </summary>
    /// <remarks>This field only applies to UAF authenticators.</remarks>
    [JsonPropertyName("ecdaaTrustAnchors")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public EcdaaTrustAnchorJSON[]? EcdaaTrustAnchors { get; }

    /// <summary>
    ///     A data: url <a href="https://www.rfc-editor.org/rfc/rfc2397.html">[RFC2397]</a> encoded <a href="https://www.w3.org/TR/png/">[PNG]</a> icon for the Authenticator.
    /// </summary>
    [JsonPropertyName("icon")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? Icon { get; }

    /// <summary>
    ///     List of extensions supported by the authenticator.
    /// </summary>
    /// <remarks>
    ///     <para>This field only applies to UAF authenticators.</para>
    ///     <para>For FIDO2 authenticators see authenticatorGetInfo.</para>
    /// </remarks>
    [JsonPropertyName("supportedExtensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ExtensionDescriptorJSON[]? SupportedExtensions { get; }

    /// <summary>
    ///     <para>Describes supported versions, extensions, AAGUID of the device and its capabilities.</para>
    ///     <para>
    ///         The information is the same reported by an authenticator when invoking the 'authenticatorGetInfo' method, see <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html">[FIDOCTAP]</a>.
    ///     </para>
    /// </summary>
    /// <remarks>
    ///     <para>This field MUST be present for FIDO 2 authenticators.</para>
    ///     <para>FIDO UAF and FIDO U2F authenticators do not support authenticatorGetInfo.</para>
    /// </remarks>
    [JsonPropertyName("authenticatorGetInfo")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public AuthenticatorGetInfoJSON? AuthenticatorGetInfo { get; }
}
