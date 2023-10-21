namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

/// <summary>
///     Display PNG Characteristics Descriptor
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#displaypngcharacteristicsdescriptor-dictionary">FIDO Metadata Statement - §3.8. DisplayPNGCharacteristicsDescriptor dictionary</a>
///     </para>
/// </remarks>
public class DisplayPngCharacteristicsDescriptor
{
    /// <summary>
    ///     Constructs <see cref="DisplayPngCharacteristicsDescriptor" />.
    /// </summary>
    /// <param name="width">image width</param>
    /// <param name="height">image height</param>
    /// <param name="bitDepth">Bit depth - bits per sample or per palette index.</param>
    /// <param name="colorType">Color type defines the PNG image type.</param>
    /// <param name="compression">Compression method used to compress the image data.</param>
    /// <param name="filter">Filter method is the preprocessing method applied to the image data before compression.</param>
    /// <param name="interlace">Interlace method is the transmission order of the image data.</param>
    /// <param name="plte">1 to 256 palette entries</param>
    public DisplayPngCharacteristicsDescriptor(
        ulong width,
        ulong height,
        byte bitDepth,
        byte colorType,
        byte compression,
        byte filter,
        byte interlace,
        RgbPaletteEntry[]? plte)
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
    public ulong Width { get; }

    /// <summary>
    ///     image height
    /// </summary>
    public ulong Height { get; }

    /// <summary>
    ///     Bit depth - bits per sample or per palette index.
    /// </summary>
    public byte BitDepth { get; }

    /// <summary>
    ///     Color type defines the PNG image type.
    /// </summary>
    public byte ColorType { get; }

    /// <summary>
    ///     Compression method used to compress the image data.
    /// </summary>
    public byte Compression { get; }

    /// <summary>
    ///     Filter method is the preprocessing method applied to the image data before compression.
    /// </summary>
    public byte Filter { get; }

    /// <summary>
    ///     Interlace method is the transmission order of the image data.
    /// </summary>
    public byte Interlace { get; }

    /// <summary>
    ///     1 to 256 palette entries
    /// </summary>
    public RgbPaletteEntry[]? Plte { get; }
}
