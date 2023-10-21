using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;

/// <summary>
///     User Verification Methods
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#user-verification-methods">FIDO Registry of Predefined Values - §3.1 User Verification Methods</a>
///     </para>
/// </remarks>
[Flags]
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum UserVerificationMethod : uint
{
    /// <summary>
    ///     This flag must be set if the authenticator is able to confirm user presence in any fashion. If this flag and no other is set for user verification, the guarantee is only that the authenticator cannot be operated without some human intervention, not necessarily that the
    ///     sensing of "presence" provides any level of user verification (e.g. a device that requires a button press to activate).
    /// </summary>
    [EnumMember(Value = "presence_internal")]
    USER_VERIFY_PRESENCE_INTERNAL = 0x00000001,

    /// <summary>
    ///     This flag must be set if the authenticator uses any type of measurement of a fingerprint for user verification.
    /// </summary>
    [EnumMember(Value = "fingerprint_internal")]
    USER_VERIFY_FINGERPRINT_INTERNAL = 0x00000002,

    /// <summary>
    ///     This flag must be set if the authenticator uses a local-only passcode (i.e. a passcode not known by the server) for user verification.
    /// </summary>
    [EnumMember(Value = "passcode_internal")]
    USER_VERIFY_PASSCODE_INTERNAL = 0x00000004,

    /// <summary>
    ///     This flag must be set if the authenticator uses a voiceprint (also known as speaker recognition) for user verification.
    /// </summary>
    [EnumMember(Value = "voiceprint_internal")]
    USER_VERIFY_VOICEPRINT_INTERNAL = 0x00000008,

    /// <summary>
    ///     This flag must be set if the authenticator uses any manner of face recognition to verify the user.
    /// </summary>
    [EnumMember(Value = "faceprint_internal")]
    USER_VERIFY_FACEPRINT_INTERNAL = 0x00000010,

    /// <summary>
    ///     This flag must be set if the authenticator uses any form of location sensor or measurement for user verification.
    /// </summary>
    [EnumMember(Value = "location_internal")]
    USER_VERIFY_LOCATION_INTERNAL = 0x00000020,

    /// <summary>
    ///     This flag must be set if the authenticator uses any form of eye biometrics for user verification.
    /// </summary>
    [EnumMember(Value = "eyeprint_internal")]
    USER_VERIFY_EYEPRINT_INTERNAL = 0x00000040,

    /// <summary>
    ///     This flag must be set if the authenticator uses a drawn pattern for user verification.
    /// </summary>
    [EnumMember(Value = "pattern_internal")]
    USER_VERIFY_PATTERN_INTERNAL = 0x00000080,

    /// <summary>
    ///     This flag must be set if the authenticator uses any measurement of a full hand (including palm-print, hand geometry or vein geometry) for user verification.
    /// </summary>
    [EnumMember(Value = "handprint_internal")]
    USER_VERIFY_HANDPRINT_INTERNAL = 0x00000100,

    /// <summary>
    ///     This flag must be set if the authenticator uses a local-only passcode (i.e. a passcode not known by the server) for user verification that might be gathered outside the authenticator boundary.
    /// </summary>
    [EnumMember(Value = "passcode_external")]
    USER_VERIFY_PASSCODE_EXTERNAL = 0x00000800,

    /// <summary>
    ///     This flag must be set if the authenticator uses a drawn pattern for user verification that might be gathered outside the authenticator boundary.
    /// </summary>
    [EnumMember(Value = "pattern_external")]
    USER_VERIFY_PATTERN_EXTERNAL = 0x00001000,

    /// <summary>
    ///     This flag must be set if the authenticator will respond without any user interaction (e.g. Silent Authenticator).
    /// </summary>
    [EnumMember(Value = "none")]
    USER_VERIFY_NONE = 0x00000200,

    /// <summary>
    ///     If an authenticator sets multiple flags for the "_INTERNAL" and/or "_EXTERNAL" user verification types, it may also set this flag to indicate that all verification methods with respective flags set will be enforced (e.g. faceprint AND voiceprint). If flags for multiple user
    ///     verification methods are set and this flag is not set, verification with only one is necessary (e.g. fingerprint OR passcode).
    /// </summary>
    [EnumMember(Value = "all")]
    USER_VERIFY_ALL = 0x00000400
}
