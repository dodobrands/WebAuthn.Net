using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.WebUtilities;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;
using WebAuthn.Net.Sample.Mvc.Constants;
using WebAuthn.Net.Sample.Mvc.Models.Common;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;

namespace WebAuthn.Net.Sample.Mvc.Models.Register;

public class ServerPublicKeyCredentialCreationOptionsRequest
{
    [JsonConstructor]
    public ServerPublicKeyCredentialCreationOptionsRequest(
        string userName,
        Dictionary<string, JsonElement>? extensions,
        AuthenticatorParameters registrationParameters)
    {
        UserName = userName;
        Extensions = extensions;
        RegistrationParameters = registrationParameters;
    }

    [JsonPropertyName("username")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string UserName { get; }

    [JsonPropertyName("registrationParameters")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public AuthenticatorParameters RegistrationParameters { get; }

    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public Dictionary<string, JsonElement>? Extensions { get; }

    public BeginRegistrationCeremonyRequest ToBeginCeremonyRequest()
    {
        var criteria = new AuthenticatorSelectionCriteria(
            RegistrationParameters.Attachment.RemapUnsetValue<AuthenticatorAttachment>(),
            RegistrationParameters.ResidentKey.RemapUnsetValue<ResidentKeyRequirement>(),
            RegistrationParameters.ResidentKeyIsRequired,
            RegistrationParameters.UserVerification.RemapUnsetValue<UserVerificationRequirement>()
        );

        return new (
            null,
            null,
            ExampleConstants.Host.WebAuthnDisplayName,
            new(UserName, WebEncoders.Base64UrlDecode(UserName), UserName),
            16,
            CoseAlgorithms.All,
            120000,
            RegistrationCeremonyExcludeCredentials.AllExisting(),
            criteria,
            null,
            RegistrationParameters.Attestation.RemapUnsetValue<AttestationConveyancePreference>(),
            null,
            Extensions);
    }
}
