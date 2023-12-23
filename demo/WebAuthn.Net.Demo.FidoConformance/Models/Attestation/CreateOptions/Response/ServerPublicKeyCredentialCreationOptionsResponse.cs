using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.Json.Serialization;
using WebAuthn.Net.Demo.FidoConformance.Constants;
using WebAuthn.Net.Demo.FidoConformance.Models.Common.Response;
using WebAuthn.Net.Models.Protocol.Json;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateOptions;

namespace WebAuthn.Net.Demo.FidoConformance.Models.Attestation.CreateOptions.Response;

public class ServerPublicKeyCredentialCreationOptionsResponse : ServerResponse
{
    [JsonConstructor]
    public ServerPublicKeyCredentialCreationOptionsResponse(
        string status,
        string errorMessage,
        PublicKeyCredentialRpEntityJSON rp,
        PublicKeyCredentialUserEntityJSON user,
        string challenge,
        PublicKeyCredentialParametersJSON[] pubKeyCredParams,
        uint? timeout,
        PublicKeyCredentialDescriptorJSON[]? excludeCredentials,
        AuthenticatorSelectionCriteriaJSON? authenticatorSelection,
        string[]? hints,
        string? attestation,
        string[]? attestationFormats,
        Dictionary<string, JsonElement>? extensions)
        : base(status, errorMessage)
    {
        Rp = rp;
        User = user;
        Challenge = challenge;
        PubKeyCredParams = pubKeyCredParams;
        Timeout = timeout;
        ExcludeCredentials = excludeCredentials;
        AuthenticatorSelection = authenticatorSelection;
        Hints = hints;
        Attestation = attestation;
        AttestationFormats = attestationFormats;
        Extensions = extensions;
    }

    [Required]
    [JsonPropertyName("rp")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public PublicKeyCredentialRpEntityJSON Rp { get; }

    [Required]
    [JsonPropertyName("user")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public PublicKeyCredentialUserEntityJSON User { get; }

    [Required]
    [JsonPropertyName("challenge")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Challenge { get; }

    [Required]
    [JsonPropertyName("pubKeyCredParams")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public PublicKeyCredentialParametersJSON[] PubKeyCredParams { get; }

    [JsonPropertyName("timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public uint? Timeout { get; }

    [JsonPropertyName("excludeCredentials")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public PublicKeyCredentialDescriptorJSON[]? ExcludeCredentials { get; }

    [JsonPropertyName("authenticatorSelection")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public AuthenticatorSelectionCriteriaJSON? AuthenticatorSelection { get; }

    [JsonPropertyName("hints")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string[]? Hints { get; }

    [JsonPropertyName("attestation")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? Attestation { get; }

    [JsonPropertyName("attestationFormats")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string[]? AttestationFormats { get; }

    [JsonPropertyName("extensions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public Dictionary<string, JsonElement>? Extensions { get; }

    public static ServerPublicKeyCredentialCreationOptionsResponse FromPublicKeyCredentialCreationOptions(
        PublicKeyCredentialCreationOptionsJSON input)
    {
        ArgumentNullException.ThrowIfNull(input);
        return new(
            ServerResponseStatus.Ok,
            string.Empty,
            input.Rp,
            input.User,
            input.Challenge,
            input.PubKeyCredParams,
            input.Timeout,
            input.ExcludeCredentials,
            input.AuthenticatorSelection,
            input.Hints,
            input.Attestation,
            input.AttestationFormats,
            input.Extensions);
    }
}
