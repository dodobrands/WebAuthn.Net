using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

/// <summary>
///     Verification Method Descriptor
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#verificationmethoddescriptor-dictionary">FIDO Metadata Statement - §3.5. VerificationMethodDescriptor dictionary</a>
///     </para>
/// </remarks>
// ReSharper disable once InconsistentNaming
public class VerificationMethodDescriptorJSON
{
    /// <summary>
    ///     Constructs <see cref="VerificationMethodDescriptorJSON" />.
    /// </summary>
    /// <param name="userVerificationMethod">
    ///     <para>a single USER_VERIFY constant case-sensitive string name. See section "User Verification Methods" in <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html">[FIDORegistry]</a> (e.g. "presence_internal"). This value MUST NOT be empty.</para>
    ///     <para>The constant USER_VERIFY_ALL MUST NOT be used here.</para>
    /// </param>
    /// <param name="caDesc">May optionally be used in the case of method USER_VERIFY_PASSCODE_INTERNAL or USER_VERIFY_PASSCODE_EXTERNAL.</param>
    /// <param name="baDesc">May optionally be used in the case of method USER_VERIFY_FINGERPRINT_INTERNAL, USER_VERIFY_VOICEPRINT_INTERNAL, USER_VERIFY_FACEPRINT_INTERNAL, USER_VERIFY_EYEPRINT_INTERNAL, or USER_VERIFY_HANDPRINT_INTERNAL.</param>
    /// <param name="paDesc">May optionally be used in case of method USER_VERIFY_PATTERN_INTERNAL or USER_VERIFY_PATTERN_EXTERNAL</param>
    [JsonConstructor]
    public VerificationMethodDescriptorJSON(
        string? userVerificationMethod,
        CodeAccuracyDescriptorJSON? caDesc,
        BiometricAccuracyDescriptorJSON? baDesc,
        PatternAccuracyDescriptorJSON? paDesc)
    {
        UserVerificationMethod = userVerificationMethod;
        CaDesc = caDesc;
        BaDesc = baDesc;
        PaDesc = paDesc;
    }

    /// <summary>
    ///     <para>a single USER_VERIFY constant case-sensitive string name. See section "User Verification Methods" in <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html">[FIDORegistry]</a> (e.g. "presence_internal"). This value MUST NOT be empty.</para>
    ///     <para>The constant USER_VERIFY_ALL MUST NOT be used here.</para>
    /// </summary>
    [JsonPropertyName("userVerificationMethod")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? UserVerificationMethod { get; }

    /// <summary>
    ///     May optionally be used in the case of method USER_VERIFY_PASSCODE_INTERNAL or USER_VERIFY_PASSCODE_EXTERNAL.
    /// </summary>
    [JsonPropertyName("caDesc")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public CodeAccuracyDescriptorJSON? CaDesc { get; }

    /// <summary>
    ///     May optionally be used in the case of method USER_VERIFY_FINGERPRINT_INTERNAL, USER_VERIFY_VOICEPRINT_INTERNAL, USER_VERIFY_FACEPRINT_INTERNAL, USER_VERIFY_EYEPRINT_INTERNAL, or USER_VERIFY_HANDPRINT_INTERNAL.
    /// </summary>
    [JsonPropertyName("baDesc")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public BiometricAccuracyDescriptorJSON? BaDesc { get; }

    /// <summary>
    ///     May optionally be used in case of method USER_VERIFY_PATTERN_INTERNAL or USER_VERIFY_PATTERN_EXTERNAL
    /// </summary>
    [JsonPropertyName("paDesc")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public PatternAccuracyDescriptorJSON? PaDesc { get; }
}
