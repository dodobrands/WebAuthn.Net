using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.WebUtilities;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Sample.Mvc.Models.Common;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;

namespace WebAuthn.Net.Sample.Mvc.Models.Passwordless;

public class ServerPublicKeyCredentialGetOptionsRequest
{

    [JsonConstructor]
    public ServerPublicKeyCredentialGetOptionsRequest(string userName, Dictionary<string, JsonElement>? extensions, string attestation, string userVerification)
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

    public BeginAuthenticationCeremonyRequest ToBeginCeremonyRequest(string userHandle)
    {
        return new(
            null,
            null,
            WebEncoders.Base64UrlDecode(userHandle),
            16,
            120000,
            AuthenticationCeremonyIncludeCredentials.AllExisting(),
            UserVerification.RemapUnsetValue<UserVerificationRequirement>(),
            null,
            Attestation.RemapUnsetValue<AttestationConveyancePreference>(),
            null,
            Extensions);
    }
}
