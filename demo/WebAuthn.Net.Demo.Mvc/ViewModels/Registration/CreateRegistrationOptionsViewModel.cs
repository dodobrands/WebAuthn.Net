using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.Json.Serialization;
using WebAuthn.Net.Demo.Mvc.Constants;
using WebAuthn.Net.Demo.Mvc.Extensions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Demo.Mvc.ViewModels.Registration;

[method: JsonConstructor]
public class CreateRegistrationOptionsViewModel(
    string userName,
    Dictionary<string, JsonElement>? extensions,
    AuthenticatorParametersViewModel registrationParameters)
{
    [JsonPropertyName("username")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string UserName { get; } = userName;

    [JsonPropertyName("registrationParameters")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public AuthenticatorParametersViewModel RegistrationParameters { get; } = registrationParameters;

    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public Dictionary<string, JsonElement>? Extensions { get; } = extensions;

    public BeginRegistrationCeremonyRequest ToBeginCeremonyRequest(byte[] userHandle)
    {
        var criteria = new AuthenticatorSelectionCriteria(
            RegistrationParameters.Attachment.RemapUnsetValue<AuthenticatorAttachment>(),
            RegistrationParameters.ResidentKey.RemapUnsetValue<ResidentKeyRequirement>(),
            RegistrationParameters.ResidentKeyIsRequired,
            RegistrationParameters.UserVerification.RemapUnsetValue<UserVerificationRequirement>()
        );
        var coseAlgorithms = RegistrationParameters.CoseAlgorithms.Select(x => (CoseAlgorithm) x).ToArray();
        return new(
            null,
            null,
            HostConstants.WebAuthnDisplayName,
            new(UserName, userHandle, UserName),
            32,
            coseAlgorithms,
            120000,
            RegistrationCeremonyExcludeCredentials.AllExisting(),
            criteria,
            null,
            RegistrationParameters.Attestation.RemapUnsetValue<AttestationConveyancePreference>(),
            null,
            Extensions);
    }
}
