using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.Json.Serialization;
using WebAuthn.Net.Demo.Mvc.Extensions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;

namespace WebAuthn.Net.Demo.Mvc.ViewModels.Passwordless;

[method: JsonConstructor]
public class PasswordlessAuthenticationViewModel(
    string userName,
    Dictionary<string, JsonElement>? extensions,
    string attestation,
    string userVerification)
{
    [JsonPropertyName("username")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string UserName { get; } = userName;

    [JsonPropertyName("attestation")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string Attestation { get; } = attestation;

    [JsonPropertyName("userVerification")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string UserVerification { get; } = userVerification;

    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public Dictionary<string, JsonElement>? Extensions { get; } = extensions;

    public BeginAuthenticationCeremonyRequest ToBeginCeremonyRequest(byte[] userHandle)
    {
        return new(
            null,
            null,
            userHandle,
            32,
            120_000,
            AuthenticationCeremonyIncludeCredentials.AllExisting(),
            UserVerification.RemapUnsetValue<UserVerificationRequirement>(),
            null,
            Attestation.RemapUnsetValue<AttestationConveyancePreference>(),
            null,
            Extensions);
    }
}
