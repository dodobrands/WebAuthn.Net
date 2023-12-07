using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

/// <summary>
///     Verification Method Descriptor
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#verificationmethoddescriptor-dictionary">FIDO Metadata Statement - §3.5. VerificationMethodDescriptor dictionary</a>
///     </para>
/// </remarks>
public class VerificationMethodDescriptor
{
    /// <summary>
    ///     Constructs <see cref="VerificationMethodDescriptor" />.
    /// </summary>
    /// <param name="userVerificationMethod">
    ///     <para>a single USER_VERIFY constant case-sensitive string name. See section "User Verification Methods" in <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html">[FIDORegistry]</a> (e.g. "presence_internal"). This value MUST NOT be empty.</para>
    ///     <para>The constant USER_VERIFY_ALL MUST NOT be used here.</para>
    /// </param>
    /// <param name="caDesc">May optionally be used in the case of method USER_VERIFY_PASSCODE_INTERNAL or USER_VERIFY_PASSCODE_EXTERNAL.</param>
    /// <param name="baDesc">May optionally be used in the case of method USER_VERIFY_FINGERPRINT_INTERNAL, USER_VERIFY_VOICEPRINT_INTERNAL, USER_VERIFY_FACEPRINT_INTERNAL, USER_VERIFY_EYEPRINT_INTERNAL, or USER_VERIFY_HANDPRINT_INTERNAL.</param>
    /// <param name="paDesc">May optionally be used in case of method USER_VERIFY_PATTERN_INTERNAL or USER_VERIFY_PATTERN_EXTERNAL</param>
    public VerificationMethodDescriptor(
        UserVerificationMethod? userVerificationMethod,
        CodeAccuracyDescriptor? caDesc,
        BiometricAccuracyDescriptor? baDesc,
        PatternAccuracyDescriptor? paDesc)
    {
        UserVerificationMethod = userVerificationMethod;
        CaDesc = caDesc;
        BaDesc = baDesc;
        PaDesc = paDesc;
    }

    /// <summary>
    ///     <para>
    ///         a single USER_VERIFY constant case-sensitive string name. See section "User Verification Methods" in <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#user-verification-methods">[FIDORegistry]</a> (e.g. "presence_internal"). This
    ///         value MUST NOT be empty.
    ///     </para>
    ///     <para>The constant USER_VERIFY_ALL MUST NOT be used here.</para>
    /// </summary>
    public UserVerificationMethod? UserVerificationMethod { get; }

    /// <summary>
    ///     May optionally be used in the case of method USER_VERIFY_PASSCODE_INTERNAL or USER_VERIFY_PASSCODE_EXTERNAL.
    /// </summary>
    public CodeAccuracyDescriptor? CaDesc { get; }

    /// <summary>
    ///     May optionally be used in the case of method USER_VERIFY_FINGERPRINT_INTERNAL, USER_VERIFY_VOICEPRINT_INTERNAL, USER_VERIFY_FACEPRINT_INTERNAL, USER_VERIFY_EYEPRINT_INTERNAL, or USER_VERIFY_HANDPRINT_INTERNAL.
    /// </summary>
    public BiometricAccuracyDescriptor? BaDesc { get; }

    /// <summary>
    ///     May optionally be used in case of method USER_VERIFY_PATTERN_INTERNAL or USER_VERIFY_PATTERN_EXTERNAL.
    /// </summary>
    public PatternAccuracyDescriptor? PaDesc { get; }
}
