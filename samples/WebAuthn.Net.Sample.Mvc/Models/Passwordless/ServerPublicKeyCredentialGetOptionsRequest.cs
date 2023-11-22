using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.WebUtilities;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;

namespace WebAuthn.Net.Sample.Mvc.Models.Passwordless;

public class ServerPublicKeyCredentialGetOptionsRequest
{

    [JsonConstructor]
    public ServerPublicKeyCredentialGetOptionsRequest(string userName, Dictionary<string, JsonElement>? extensions)
    {
        UserName = userName;
        Extensions = extensions;
    }

    [JsonPropertyName("username")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string UserName { get; }

    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public Dictionary<string, JsonElement>? Extensions { get; }

    public BeginAuthenticationCeremonyRequest ToBeginCeremonyRequest()
    {
        return new(
            null,
            null,
            WebEncoders.Base64UrlDecode(UserName),
            16,
            120000,
            AuthenticationCeremonyIncludeCredentials.AllExisting(),
            UserVerificationRequirement.Preferred,
            null,
            null,
            null,
            Extensions);
    }
}
