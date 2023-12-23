using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Demo.Mvc.ViewModels.Registration;

public class AuthenticatorParametersViewModel
{
    [JsonConstructor]
    public AuthenticatorParametersViewModel(string userVerification, string attachment, string discoverableCredential, string attestation, string residentKey, CoseAlgorithm[] coseAlgorithms)
    {
        UserVerification = userVerification;
        Attachment = attachment;
        DiscoverableCredential = discoverableCredential;
        Attestation = attestation;
        ResidentKey = residentKey;
        CoseAlgorithms = coseAlgorithms;
    }

    [JsonPropertyName("userVerification")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string UserVerification { get; }

    [JsonPropertyName("attachment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string Attachment { get; }

    [JsonPropertyName("discoverableCredential")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string DiscoverableCredential { get; }

    [JsonPropertyName("attestation")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string Attestation { get; }

    [JsonPropertyName("residentKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string ResidentKey { get; }

    [JsonPropertyName("pubKeyCredParams")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public CoseAlgorithm[] CoseAlgorithms { get; }

    public bool ResidentKeyIsRequired => ResidentKey.Equals("unset", StringComparison.Ordinal);
}
