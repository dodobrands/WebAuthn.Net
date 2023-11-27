using System.ComponentModel.DataAnnotations;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Sample.Mvc.Models.Common;

internal static class AuthenticatorParametersHelpers
{
    internal static T? RemapUnsetValue<T>(this string value) where T : struct, Enum
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Equals("unset", StringComparison.Ordinal)) return null;

        var enumType = typeof(T);
        foreach (var name in Enum.GetNames(enumType))
        {
            var enumMemberAttribute = ((EnumMemberAttribute[]) enumType
                    .GetField(name)!
                    .GetCustomAttributes(typeof(EnumMemberAttribute), true))
                    .Single();

            if (enumMemberAttribute.Value == value) return (T)Enum.Parse(enumType, name);
        }

        return null;
    }
}

public class AuthenticatorParameters
{
    [JsonConstructor]
    public AuthenticatorParameters(string userVerification, string attachment, string discoverableCredential, string attestation, string residentKey)
    {
        UserVerification = userVerification;
        Attachment = attachment;
        DiscoverableCredential = discoverableCredential;
        Attestation = attestation;
        ResidentKey = residentKey;
    }

    [JsonPropertyName("userVerification")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string UserVerification { get; }
    [JsonPropertyName("attachment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string Attachment { get; }
    [JsonPropertyName("discoverableCredential")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string DiscoverableCredential { get; }
    [JsonPropertyName("attestation")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string Attestation { get; }
    [JsonPropertyName("residentKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string ResidentKey { get; }
    public bool ResidentKeyIsRequired => ResidentKey.Equals("unset", StringComparison.Ordinal);
}
