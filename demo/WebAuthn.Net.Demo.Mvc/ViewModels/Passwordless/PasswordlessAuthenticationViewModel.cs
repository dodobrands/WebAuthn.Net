using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.Json.Serialization;
using WebAuthn.Net.Demo.Mvc.Extensions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;

namespace WebAuthn.Net.Demo.Mvc.ViewModels.Passwordless;

public class PasswordlessAuthenticationViewModel
{
    [JsonConstructor]
    public PasswordlessAuthenticationViewModel(string userName, Dictionary<string, JsonElement>? extensions, string attestation, string userVerification)
    {
        UserName = userName;
        Extensions = extensions;
        Attestation = attestation;
        UserVerification = userVerification;
    }

    [JsonPropertyName("username")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string UserName { get; }

    [JsonPropertyName("attestation")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string Attestation { get; }

    [JsonPropertyName("userVerification")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string UserVerification { get; }

    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public Dictionary<string, JsonElement>? Extensions { get; }

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
