using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using WebAuthn.Net.Serialization.Json;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.Enums;

[JsonConverter(typeof(EnumAsStringConverter<AttestationStatementFormat>))]
public enum AttestationStatementFormat
{
    [EnumMember(Value = "packed")]
    Packed = 0,

    [EnumMember(Value = "tpm")]
    Tpm = 1,

    [EnumMember(Value = "android-key")]
    AndroidKey = 2,

    [EnumMember(Value = "android-safetynet")]
    AndroidSafetynet = 3,

    [EnumMember(Value = "fido-u2f")]
    FidoU2F = 4,

    [EnumMember(Value = "none")]
    None = 5,

    [EnumMember(Value = "apple")]
    AppleAnonymous = 6
}
