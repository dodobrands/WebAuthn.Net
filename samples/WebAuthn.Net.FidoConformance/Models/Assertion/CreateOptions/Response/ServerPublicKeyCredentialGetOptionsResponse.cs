using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using WebAuthn.Net.FidoConformance.Constants;
using WebAuthn.Net.FidoConformance.Models.Common.Response;
using WebAuthn.Net.Models.Protocol.Json;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.CreateOptions;

namespace WebAuthn.Net.FidoConformance.Models.Assertion.CreateOptions.Response;

public class ServerPublicKeyCredentialGetOptionsResponse : ServerResponse
{
    [JsonConstructor]
    public ServerPublicKeyCredentialGetOptionsResponse(
        string status,
        string errorMessage,
        string challenge,
        uint? timeout,
        string? rpId,
        PublicKeyCredentialDescriptorJSON[]? allowCredentials,
        string? userVerification) : base(status, errorMessage)
    {
        Challenge = challenge;
        Timeout = timeout;
        RpId = rpId;
        AllowCredentials = allowCredentials;
        UserVerification = userVerification;
    }

    [Required]
    [JsonPropertyName("challenge")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Challenge { get; }

    [JsonPropertyName("timeout")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public uint? Timeout { get; }

    [JsonPropertyName("rpId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? RpId { get; }

    [JsonPropertyName("allowCredentials")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public PublicKeyCredentialDescriptorJSON[]? AllowCredentials { get; }

    [JsonPropertyName("userVerification")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? UserVerification { get; }

    public static ServerPublicKeyCredentialGetOptionsResponse FromPublicKeyCredentialRequestOptions(PublicKeyCredentialRequestOptionsJSON input)
    {
        ArgumentNullException.ThrowIfNull(input);
        return new(
            ServerResponseStatus.Ok,
            string.Empty,
            input.Challenge,
            input.Timeout,
            input.RpId,
            input.AllowCredentials,
            input.UserVerification);
    }
}
