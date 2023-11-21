using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.Common.ClientDataDecoder.Implementation.Models;

public class CollectedClientDataJson
{
    [JsonConstructor]
    public CollectedClientDataJson(
        string type,
        string challenge,
        string origin,
        string? topOrigin,
        bool? crossOrigin,
        TokenBindingJson? tokenBinding)
    {
        Type = type;
        Challenge = challenge;
        Origin = origin;
        TopOrigin = topOrigin;
        CrossOrigin = crossOrigin;
        TokenBinding = tokenBinding;
    }

    [JsonPropertyName("type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string Type { get; }

    [JsonPropertyName("challenge")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Challenge { get; }

    [JsonPropertyName("origin")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string Origin { get; }

    [JsonPropertyName("topOrigin")]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    [Required]
    public string? TopOrigin { get; }

    [JsonPropertyName("crossOrigin")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? CrossOrigin { get; }

    [JsonPropertyName("tokenBinding")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public TokenBindingJson? TokenBinding { get; }
}
