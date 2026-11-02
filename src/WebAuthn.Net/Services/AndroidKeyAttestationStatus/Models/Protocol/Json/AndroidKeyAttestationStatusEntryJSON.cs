using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models.Protocol.Json;

/// <summary>
///     An entry of the <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a> of the Android attestation keys:
///     the status of an attestation key that doesn't have a normal valid status.
/// </summary>
/// <remarks>
///     Only the members that the library uses are declared. The other members of an entry ('expires' and 'comment') are ignored, so that their format can't make the whole status list invalid.
/// </remarks>
// ReSharper disable once InconsistentNaming
public class AndroidKeyAttestationStatusEntryJSON
{
    /// <summary>
    ///     Constructs <see cref="AndroidKeyAttestationStatusEntryJSON" />.
    /// </summary>
    /// <param name="status">Current status of the key: REVOKED or SUSPENDED.</param>
    /// <param name="reason">Reason for the current status: UNSPECIFIED, KEY_COMPROMISE, CA_COMPROMISE, SUPERSEDED or SOFTWARE_FLAW.</param>
    [JsonConstructor]
    public AndroidKeyAttestationStatusEntryJSON(string? status, string? reason)
    {
        Status = status;
        Reason = reason;
    }

    /// <summary>
    ///     Current status of the key: REVOKED or SUSPENDED.
    /// </summary>
    [JsonPropertyName("status")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public string? Status { get; }

    /// <summary>
    ///     Reason for the current status: UNSPECIFIED, KEY_COMPROMISE, CA_COMPROMISE, SUPERSEDED or SOFTWARE_FLAW.
    /// </summary>
    [JsonPropertyName("reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public string? Reason { get; }
}
