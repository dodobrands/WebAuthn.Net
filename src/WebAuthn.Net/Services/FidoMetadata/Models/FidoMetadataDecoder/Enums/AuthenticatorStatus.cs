using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;

/// <summary>
///     Authenticator Status
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-authnr-stat">FIDO Metadata Service - AuthenticatorStatus enum</a>
///     </para>
/// </remarks>
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum AuthenticatorStatus : uint
{
    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Certification Related Status</a>
    ///     </para>
    ///     <para>This authenticator is not FIDO certified.</para>
    /// </summary>
    [EnumMember(Value = "NOT_FIDO_CERTIFIED")]
    NOT_FIDO_CERTIFIED = 1,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Certification Related Status</a>
    ///     </para>
    ///     <para>The authenticator vendor has completed and submitted the self-certification checklist to the FIDO Alliance. If this completed checklist is publicly available, the URL will be specified in url.</para>
    /// </summary>
    [EnumMember(Value = "SELF_ASSERTION_SUBMITTED")]
    SELF_ASSERTION_SUBMITTED = 2,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Certification Related Status</a>
    ///     </para>
    ///     <para>This authenticator has passed FIDO functional certification. This certification scheme is phased out and will be replaced by FIDO_CERTIFIED_L1.</para>
    /// </summary>
    [EnumMember(Value = "FIDO_CERTIFIED")]
    FIDO_CERTIFIED = 3,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Certification Related Status</a>
    ///     </para>
    ///     <para>The authenticator has passed FIDO Authenticator certification at level 1. This level is the more strict successor of FIDO_CERTIFIED.</para>
    /// </summary>
    [EnumMember(Value = "FIDO_CERTIFIED_L1")]
    FIDO_CERTIFIED_L1 = 4,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Certification Related Status</a>
    ///     </para>
    ///     <para>The authenticator has passed FIDO Authenticator certification at level 1+. This level is the more than level 1.</para>
    /// </summary>
    [EnumMember(Value = "FIDO_CERTIFIED_L1plus")]
    FIDO_CERTIFIED_L1plus = 5,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Certification Related Status</a>
    ///     </para>
    ///     <para>The authenticator has passed FIDO Authenticator certification at level 2. This level is more strict than level 1+.</para>
    /// </summary>
    [EnumMember(Value = "FIDO_CERTIFIED_L2")]
    FIDO_CERTIFIED_L2 = 6,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Certification Related Status</a>
    ///     </para>
    ///     <para>The authenticator has passed FIDO Authenticator certification at level 2+. This level is more strict than level 2.</para>
    /// </summary>
    [EnumMember(Value = "FIDO_CERTIFIED_L2plus")]
    FIDO_CERTIFIED_L2plus = 7,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Certification Related Status</a>
    ///     </para>
    ///     <para>The authenticator has passed FIDO Authenticator certification at level 3. This level is more strict than level 2+.</para>
    /// </summary>
    [EnumMember(Value = "FIDO_CERTIFIED_L3")]
    FIDO_CERTIFIED_L3 = 8,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Certification Related Status</a>
    ///     </para>
    ///     <para>The authenticator has passed FIDO Authenticator certification at level 3+. This level is more strict than level 3.</para>
    /// </summary>
    [EnumMember(Value = "FIDO_CERTIFIED_L3plus")]
    FIDO_CERTIFIED_L3plus = 9,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Certification Related Status</a>
    ///     </para>
    ///     <para>The authenticator has passed FIPS 140 certification at overall level 1.</para>
    /// </summary>
    [EnumMember(Value = "FIPS140_CERTIFIED_L1")]
    FIPS140_CERTIFIED_L1 = 16,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Certification Related Status</a>
    ///     </para>
    ///     <para>The authenticator has passed FIPS 140 certification at overall level 2.</para>
    /// </summary>
    [EnumMember(Value = "FIPS140_CERTIFIED_L2")]
    FIPS140_CERTIFIED_L2 = 17,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Certification Related Status</a>
    ///     </para>
    ///     <para>The authenticator has passed FIPS 140 certification at overall level 3.</para>
    /// </summary>
    [EnumMember(Value = "FIPS140_CERTIFIED_L3")]
    FIPS140_CERTIFIED_L3 = 18,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Certification Related Status</a>
    ///     </para>
    ///     <para>The authenticator has passed FIPS 140 certification at overall level 4.</para>
    /// </summary>
    [EnumMember(Value = "FIPS140_CERTIFIED_L4")]
    FIPS140_CERTIFIED_L4 = 19,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Certification Related Status</a>
    ///     </para>
    ///     <para>
    ///         The authenticator vendor has decided to retire the product, that this authenticator should not be accepted any longer. For example if a prototype version of the authenticator was added to FIDO MDS and has now been superseded by the final product, the entry for the
    ///         prototype might be set to "retired".
    ///     </para>
    ///     <para>The effectiveDate field is the date of retirement. The url field is the URL to the news/corporate article explaining the reason for retirement.</para>
    /// </summary>
    [EnumMember(Value = "RETIRED")]
    RETIRED = 20,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Certification Related Status</a>
    ///     </para>
    ///     <para>The FIDO Alliance has determined that this authenticator should not be trusted for any reason. For example if it is known to be a fraudulent product or contain a deliberate backdoor. Relying parties SHOULD reject any future registration of this authenticator model.</para>
    /// </summary>
    [EnumMember(Value = "REVOKED")]
    REVOKED = 10,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Security Notification Status</a>
    ///     </para>
    ///     <para>Indicates that malware is able to bypass the user verification. This means that the authenticator could be used without the user’s consent and potentially even without the user’s knowledge.</para>
    /// </summary>
    [EnumMember(Value = "USER_VERIFICATION_BYPASS")]
    USER_VERIFICATION_BYPASS = 11,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Security Notification Status</a>
    ///     </para>
    ///     <para>
    ///         Indicates that an attestation key for this authenticator is known to be compromised. The relying party SHOULD check the certificate field and use it to identify the compromised authenticator batch. If the certificate field is not set, the relying party should reject
    ///         all new registrations of the compromised authenticator. The Authenticator manufacturer should set the date to the date when compromise has occurred.
    ///     </para>
    /// </summary>
    [EnumMember(Value = "ATTESTATION_KEY_COMPROMISE")]
    ATTESTATION_KEY_COMPROMISE = 12,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Security Notification Status</a>
    ///     </para>
    ///     <para>
    ///         This authenticator has identified weaknesses that allow registered keys to be compromised and should not be trusted. This would include both, e.g. weak entropy that causes predictable keys to be generated or side channels that allow keys or signatures to be forged,
    ///         guessed or extracted.
    ///     </para>
    /// </summary>
    [EnumMember(Value = "USER_KEY_REMOTE_COMPROMISE")]
    USER_KEY_REMOTE_COMPROMISE = 13,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Security Notification Status</a>
    ///     </para>
    ///     <para>This authenticator has known weaknesses in its key protection mechanism(s) that allow user keys to be extracted by an adversary in physical possession of the device.</para>
    /// </summary>
    [EnumMember(Value = "USER_KEY_PHYSICAL_COMPROMISE")]
    USER_KEY_PHYSICAL_COMPROMISE = 14,

    /// <summary>
    ///     <para>
    ///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-cert-stats">Security Notification Status</a>
    ///     </para>
    ///     <para>A software or firmware update is available for the device. The Authenticator manufacturer should set the url to the URL where users can obtain an update and the date the update was published.</para>
    /// </summary>
    [EnumMember(Value = "UPDATE_AVAILABLE")]
    UPDATE_AVAILABLE = 15
}
