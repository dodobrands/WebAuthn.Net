using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using WebAuthn.Net.Serialization.Json;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.Enums;

[JsonConverter(typeof(EnumAsStringConverter<AttestationStatementFormat>))]
public enum AttestationStatementFormat
{
    [EnumMember(Value = "packed")]
    Packed = 0
}
