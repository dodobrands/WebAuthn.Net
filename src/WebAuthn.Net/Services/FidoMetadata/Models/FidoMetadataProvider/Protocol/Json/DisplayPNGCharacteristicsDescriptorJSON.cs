using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

/// <summary>
///     Display PNG Characteristics Descriptor
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#displaypngcharacteristicsdescriptor-dictionary">FIDO Metadata Statement - §3.8. DisplayPNGCharacteristicsDescriptor dictionary</a>
///     </para>
/// </remarks>
// ReSharper disable once InconsistentNaming
public class DisplayPNGCharacteristicsDescriptorJSON
{
    /// <summary>
    ///     Constructs <see cref="DisplayPNGCharacteristicsDescriptorJSON" />.
    /// </summary>
    /// <param name="width">image width</param>
    /// <param name="height">image height</param>
    /// <param name="bitDepth">Bit depth - bits per sample or per palette index.</param>
    /// <param name="colorType">Color type defines the PNG image type.</param>
    /// <param name="compression">Compression method used to compress the image data.</param>
    /// <param name="filter">Filter method is the preprocessing method applied to the image data before compression.</param>
    /// <param name="interlace">Interlace method is the transmission order of the image data.</param>
    /// <param name="plte">1 to 256 palette entries</param>
    [JsonConstructor]
    public DisplayPNGCharacteristicsDescriptorJSON(
        uint width,
        uint height,
        byte bitDepth,
        byte colorType,
        byte compression,
        byte filter,
        byte interlace,
        RgbPaletteEntryJSON[]? plte)
    {
        Width = width;
        Height = height;
        BitDepth = bitDepth;
        ColorType = colorType;
        Compression = compression;
        Filter = filter;
        Interlace = interlace;
        Plte = plte;
    }

    /// <summary>
    ///     image width
    /// </summary>
    [JsonPropertyName("width")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public uint Width { get; }

    /// <summary>
    ///     image height
    /// </summary>
    [JsonPropertyName("height")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public uint Height { get; }

    /// <summary>
    ///     Bit depth - bits per sample or per palette index.
    /// </summary>
    [JsonPropertyName("bitDepth")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public byte BitDepth { get; }

    /// <summary>
    ///     Color type defines the PNG image type.
    /// </summary>
    [JsonPropertyName("colorType")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public byte ColorType { get; }

    /// <summary>
    ///     Compression method used to compress the image data.
    /// </summary>
    [JsonPropertyName("compression")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public byte Compression { get; }

    /// <summary>
    ///     Filter method is the preprocessing method applied to the image data before compression.
    /// </summary>
    [JsonPropertyName("filter")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public byte Filter { get; }

    /// <summary>
    ///     Interlace method is the transmission order of the image data.
    /// </summary>
    [JsonPropertyName("interlace")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public byte Interlace { get; }

    /// <summary>
    ///     1 to 256 palette entries
    /// </summary>
    [JsonPropertyName("plte")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public RgbPaletteEntryJSON[]? Plte { get; }
}
