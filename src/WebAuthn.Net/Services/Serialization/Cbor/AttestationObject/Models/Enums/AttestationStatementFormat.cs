using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using WebAuthn.Net.Serialization.Json;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.Enums;

[JsonConverter(typeof(EnumAsStringConverter<AttestationStatementFormat>))]
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum AttestationStatementFormat
{
    [EnumMember(Value = "none")]
    None = 0,

    [EnumMember(Value = "packed")]
    Packed = 1,

    [EnumMember(Value = "tpm")]
    Tpm = 2,

    [EnumMember(Value = "android-key")]
    AndroidKey = 3,

    [EnumMember(Value = "android-safetynet")]
    AndroidSafetynet = 4,

    [EnumMember(Value = "fido-u2f")]
    FidoU2f = 5,

    [EnumMember(Value = "apple")]
    Apple = 6
}
