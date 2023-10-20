using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

/// <summary>
///     Code Accuracy Descriptor
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#codeaccuracydescriptor-dictionary">FIDO Metadata Statement - §3.2. CodeAccuracyDescriptor dictionary</a>
///     </para>
/// </remarks>
// ReSharper disable once InconsistentNaming
public class CodeAccuracyDescriptorJSON
{
    /// <summary>
    ///     Constructs <see cref="CodeAccuracyDescriptorJSON" />.
    /// </summary>
    /// <param name="base">The numeric system base (radix) of the code, e.g. 10 in the case of decimal digits.</param>
    /// <param name="minLength">The minimum number of digits of the given base required for that code, e.g. 4 in the case of 4 digits.</param>
    /// <param name="maxRetries">Maximum number of false attempts before the authenticator will block this method (at least for some time). 0 means it will never block.</param>
    /// <param name="blockSlowdown">
    ///     Enforced minimum number of seconds wait time after blocking (e.g. due to forced reboot or similar). 0 means this user verification method will be blocked, either permanently or until an alternative user verification method method succeeded. All
    ///     alternative user verification methods MUST be specified appropriately in the Metadata in userVerificationDetails.
    /// </param>
    [JsonConstructor]
    public CodeAccuracyDescriptorJSON(
        ushort @base,
        ushort minLength,
        ushort? maxRetries,
        ushort? blockSlowdown)
    {
        Base = @base;
        MinLength = minLength;
        MaxRetries = maxRetries;
        BlockSlowdown = blockSlowdown;
    }

    /// <summary>
    ///     The numeric system base (radix) of the code, e.g. 10 in the case of decimal digits.
    /// </summary>
    [JsonPropertyName("base")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public ushort Base { get; }

    /// <summary>
    ///     The minimum number of digits of the given base required for that code, e.g. 4 in the case of 4 digits.
    /// </summary>
    [JsonPropertyName("minLength")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public ushort MinLength { get; }

    /// <summary>
    ///     Maximum number of false attempts before the authenticator will block this method (at least for some time). 0 means it will never block.
    /// </summary>
    [JsonPropertyName("maxRetries")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ushort? MaxRetries { get; }

    /// <summary>
    ///     Enforced minimum number of seconds wait time after blocking (e.g. due to forced reboot or similar). 0 means this user verification method will be blocked, either permanently or until an alternative user verification method method succeeded. All alternative user verification
    ///     methods MUST be specified appropriately in the Metadata in userVerificationDetails.
    /// </summary>
    [JsonPropertyName("blockSlowdown")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ushort? BlockSlowdown { get; }
}
