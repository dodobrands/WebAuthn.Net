using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models.Protocol.Json;

/// <summary>
///     The <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a> of the Android attestation keys, as Google serves it.
/// </summary>
// ReSharper disable once InconsistentNaming
public class AndroidKeyAttestationStatusListJSON
{
    /// <summary>
    ///     Constructs <see cref="AndroidKeyAttestationStatusListJSON" />.
    /// </summary>
    /// <param name="entries">Each entry represents the status of an attestation key. The dictionary-key is the certificate serial number in lowercase hex.</param>
    [JsonConstructor]
    public AndroidKeyAttestationStatusListJSON(Dictionary<string, AndroidKeyAttestationStatusEntryJSON?>? entries)
    {
        Entries = entries;
    }

    /// <summary>
    ///     Each entry represents the status of an attestation key. The dictionary-key is the certificate serial number in lowercase hex.
    /// </summary>
    [JsonPropertyName("entries")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public Dictionary<string, AndroidKeyAttestationStatusEntryJSON?>? Entries { get; }
}
