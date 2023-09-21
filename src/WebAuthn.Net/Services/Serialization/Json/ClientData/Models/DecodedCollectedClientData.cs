using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.Serialization.Json.ClientData.Models;

public class DecodedCollectedClientData
{
    public DecodedCollectedClientData(string type, string challenge, string origin, bool? crossOrigin)
    {
        Type = type;
        Challenge = challenge;
        Origin = origin;
        CrossOrigin = crossOrigin;
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

    [JsonPropertyName("crossOrigin")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? CrossOrigin { get; }
}