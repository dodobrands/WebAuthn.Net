using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.Common.ClientDataDecoder.Implementation.Models;

public class TokenBindingJson
{
    [JsonConstructor]
    public TokenBindingJson(string status, string? id)
    {
        Status = status;
        Id = id;
    }

    [JsonPropertyName("status")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string Status { get; }

    [JsonPropertyName("id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? Id { get; }
}
