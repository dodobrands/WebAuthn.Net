using System.Runtime.Serialization;

namespace WebAuthn.Net.Models.Enums;

public enum UserVerificationRequirement
{
    [EnumMember(Value = "required")]
    Required = 0,

    [EnumMember(Value = "preferred")]
    Preferred = 1,

    [EnumMember(Value = "discouraged")]
    Discouraged = 2
}
