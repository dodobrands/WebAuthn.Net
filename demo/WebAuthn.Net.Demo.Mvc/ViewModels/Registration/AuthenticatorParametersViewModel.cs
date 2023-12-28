using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Demo.Mvc.ViewModels.Registration;

[method: JsonConstructor]
public class AuthenticatorParametersViewModel(
    string userVerification,
    string attachment,
    string discoverableCredential,
    string attestation,
    string residentKey,
    int[] coseAlgorithms)
{
    [JsonPropertyName("userVerification")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string UserVerification { get; } = userVerification;

    [JsonPropertyName("attachment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string Attachment { get; } = attachment;

    [JsonPropertyName("discoverableCredential")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string DiscoverableCredential { get; } = discoverableCredential;

    [JsonPropertyName("attestation")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string Attestation { get; } = attestation;

    [JsonPropertyName("residentKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string ResidentKey { get; } = residentKey;

    [JsonPropertyName("pubKeyCredParams")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public int[] CoseAlgorithms { get; } = coseAlgorithms;

    public bool ResidentKeyIsRequired => ResidentKey.Equals("unset", StringComparison.Ordinal);
}
