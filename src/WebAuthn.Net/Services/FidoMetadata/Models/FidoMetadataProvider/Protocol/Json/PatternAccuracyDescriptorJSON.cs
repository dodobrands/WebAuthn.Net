using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

/// <summary>
///     Pattern Accuracy Descriptor
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#patternaccuracydescriptor-dictionary">FIDO Metadata Statement - §3.4. PatternAccuracyDescriptor dictionary</a>
///     </para>
/// </remarks>
// ReSharper disable once InconsistentNaming
public class PatternAccuracyDescriptorJSON
{
    /// <summary>
    ///     Constructs <see cref="PatternAccuracyDescriptorJSON" />.
    /// </summary>
    /// <param name="minComplexity">Number of possible patterns (having the minimum length) out of which exactly one would be the right one, i.e. 1/probability in the case of equal distribution.</param>
    /// <param name="maxRetries">Maximum number of false attempts before the authenticator will block authentication using this method (at least temporarily). 0 means it will never block.</param>
    /// <param name="blockSlowdown">
    ///     Enforced minimum number of seconds wait time after blocking (due to forced reboot or similar mechanism). 0 means this user verification method will be blocked, either permanently or until an alternative user verification method method succeeded. All
    ///     alternative user verification methods MUST be specified appropriately in the metadata under userVerificationDetails.
    /// </param>
    [JsonConstructor]
    public PatternAccuracyDescriptorJSON(
        uint minComplexity,
        ushort? maxRetries,
        ushort? blockSlowdown)
    {
        MinComplexity = minComplexity;
        MaxRetries = maxRetries;
        BlockSlowdown = blockSlowdown;
    }

    /// <summary>
    ///     Number of possible patterns (having the minimum length) out of which exactly one would be the right one, i.e. 1/probability in the case of equal distribution.
    /// </summary>
    [JsonPropertyName("minComplexity")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public uint MinComplexity { get; }

    /// <summary>
    ///     Maximum number of false attempts before the authenticator will block authentication using this method (at least temporarily). 0 means it will never block.
    /// </summary>
    [JsonPropertyName("maxRetries")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ushort? MaxRetries { get; }

    /// <summary>
    ///     Enforced minimum number of seconds wait time after blocking (due to forced reboot or similar mechanism). 0 means this user verification method will be blocked, either permanently or until an alternative user verification method method succeeded. All alternative user
    ///     verification methods MUST be specified appropriately in the metadata under userVerificationDetails.
    /// </summary>
    [JsonPropertyName("blockSlowdown")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ushort? BlockSlowdown { get; }
}
