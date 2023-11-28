using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.WebUtilities;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;
using WebAuthn.Net.Sample.Mvc.Constants;
using WebAuthn.Net.Sample.Mvc.Models.Common;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;

namespace WebAuthn.Net.Sample.Mvc.Models.Usernameless;

public class RegisterPublicKeyCredentialCreationOptionsRequest
{
    [JsonConstructor]
    public RegisterPublicKeyCredentialCreationOptionsRequest(Dictionary<string, JsonElement>? extensions)
    {
        Extensions = extensions;
    }

    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public Dictionary<string, JsonElement>? Extensions { get; }

    public BeginRegistrationCeremonyRequest ToBeginCeremonyRequest()
    {
        var name = "Anonymous (Usernameless)";
        var criteria = new AuthenticatorSelectionCriteria(
            AuthenticatorAttachment.CrossPlatform,
            ResidentKeyRequirement.Required,
            true,
            null
        );

        return new (
            null,
            null,
            ExampleConstants.Host.WebAuthnDisplayName,
            new(name, WebEncoders.Base64UrlDecode(Guid.NewGuid().ToString()), name),
            16,
            CoseAlgorithms.All,
            120000,
            RegistrationCeremonyExcludeCredentials.AllExisting(),
            criteria,
            null,
            null,
            null,
            Extensions);
    }
}
