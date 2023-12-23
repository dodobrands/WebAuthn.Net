using System.Text.Json;
using System.Text.Json.Serialization;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;

namespace WebAuthn.Net.Demo.Mvc.ViewModels.Usernameless;

public class UsernamelessAuthenticationViewModel
{
    [JsonConstructor]
    public UsernamelessAuthenticationViewModel(Dictionary<string, JsonElement>? extensions)
    {
        Extensions = extensions;
    }

    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public Dictionary<string, JsonElement>? Extensions { get; }

    public BeginAuthenticationCeremonyRequest ToBeginCeremonyRequest()
    {
        return new(
            null,
            null,
            null,
            32,
            120000,
            AuthenticationCeremonyIncludeCredentials.AllExisting(),
            null,
            null,
            null,
            null,
            Extensions);
    }
}
