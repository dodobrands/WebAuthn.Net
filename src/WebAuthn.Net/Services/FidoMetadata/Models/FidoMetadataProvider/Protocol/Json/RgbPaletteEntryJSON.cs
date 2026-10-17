using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

/// <summary>
///     RGB Palette Entry
/// </summary>
/// <remarks>
///     <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html#sctn-type-rgbpe">FIDO Metadata Statement - rgbPaletteEntry dictionary</a>
/// </remarks>
// ReSharper disable once InconsistentNaming
public class RgbPaletteEntryJSON
{
    /// <summary>
    ///     Constructs <see cref="RgbPaletteEntryJSON" />.
    /// </summary>
    /// <param name="r">Red channel sample value</param>
    /// <param name="g">Green channel sample value</param>
    /// <param name="b">Blue channel sample value</param>
    [JsonConstructor]
    public RgbPaletteEntryJSON(
        ushort r,
        ushort g,
        ushort b)
    {
        R = r;
        G = g;
        B = b;
    }

    /// <summary>
    ///     Red channel sample value
    /// </summary>
    [JsonPropertyName("r")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public ushort R { get; }

    /// <summary>
    ///     Green channel sample value
    /// </summary>
    [JsonPropertyName("g")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public ushort G { get; }

    /// <summary>
    ///     Blue channel sample value
    /// </summary>
    [JsonPropertyName("b")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public ushort B { get; }
}
