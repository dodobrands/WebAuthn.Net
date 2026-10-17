using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

/// <summary>
///     Display PNG Characteristics Descriptor
/// </summary>
/// <remarks>
///     <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html#sctn-type-dpngcd">FIDO Metadata Statement - DisplayPNGCharacteristicsDescriptor dictionary</a>
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
        ulong width,
        ulong height,
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
    public ulong Width { get; }

    /// <summary>
    ///     image height
    /// </summary>
    [JsonPropertyName("height")]
    [Required]
    [JsonIgnore(Condition = JsonIgnoreCondition.Never)]
    public ulong Height { get; }

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
