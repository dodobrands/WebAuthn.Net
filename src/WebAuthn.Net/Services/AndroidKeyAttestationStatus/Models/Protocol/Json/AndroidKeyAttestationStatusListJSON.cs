using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models.Protocol.Json;

/// <summary>
///     The <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a> of the Android attestation keys, as Google serves it.
/// </summary>
/// <remarks>
///     The entries are kept as JSON elements, so that a malformed entry can be handled on its own instead of failing the whole status list.
/// </remarks>
// ReSharper disable once InconsistentNaming
public class AndroidKeyAttestationStatusListJSON
{
    /// <summary>
    ///     Constructs <see cref="AndroidKeyAttestationStatusListJSON" />.
    /// </summary>
    /// <param name="entries">The status of each attestation key that doesn't have a normal valid status, by the serial number of its certificate in lowercase hexadecimal.</param>
    [JsonConstructor]
    public AndroidKeyAttestationStatusListJSON(Dictionary<string, JsonElement>? entries)
    {
        Entries = entries;
    }

    /// <summary>
    ///     The status of each attestation key that doesn't have a normal valid status, by the serial number of its certificate in lowercase hexadecimal.
    ///     <see langword="null" /> if the member is absent or <see langword="null" />.
    /// </summary>
    [JsonPropertyName("entries")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public Dictionary<string, JsonElement>? Entries { get; }
}
