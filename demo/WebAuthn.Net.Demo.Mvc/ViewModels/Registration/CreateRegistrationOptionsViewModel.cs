using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.Json.Serialization;
using WebAuthn.Net.Demo.Mvc.Constants;
using WebAuthn.Net.Demo.Mvc.Extensions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;

namespace WebAuthn.Net.Demo.Mvc.ViewModels.Registration;

public class CreateRegistrationOptionsViewModel
{
    [JsonConstructor]
    public CreateRegistrationOptionsViewModel(
        string userName,
        Dictionary<string, JsonElement>? extensions,
        AuthenticatorParametersViewModel registrationParameters)
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
    public AuthenticatorParametersViewModel RegistrationParameters { get; }

    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public Dictionary<string, JsonElement>? Extensions { get; }

    public BeginRegistrationCeremonyRequest ToBeginCeremonyRequest(byte[] userHandle)
    {
        var criteria = new AuthenticatorSelectionCriteria(
            RegistrationParameters.Attachment.RemapUnsetValue<AuthenticatorAttachment>(),
            RegistrationParameters.ResidentKey.RemapUnsetValue<ResidentKeyRequirement>(),
            RegistrationParameters.ResidentKeyIsRequired,
            RegistrationParameters.UserVerification.RemapUnsetValue<UserVerificationRequirement>()
        );

        return new(
            null,
            null,
            HostConstants.WebAuthnDisplayName,
            new(UserName, userHandle, UserName),
            32,
            RegistrationParameters.CoseAlgorithms,
            120000,
            RegistrationCeremonyExcludeCredentials.AllExisting(),
            criteria,
            null,
            RegistrationParameters.Attestation.RemapUnsetValue<AttestationConveyancePreference>(),
            null,
            Extensions);
    }
}
