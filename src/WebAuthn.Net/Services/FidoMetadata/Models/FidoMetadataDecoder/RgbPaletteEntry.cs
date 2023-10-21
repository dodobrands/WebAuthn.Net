namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

/// <summary>
///     RGB Palette Entry
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#rgbpaletteentry-dictionary">FIDO Metadata Statement - §3.7. rgbPaletteEntry dictionary</a>
///     </para>
/// </remarks>
public class RgbPaletteEntry
{
    /// <summary>
    ///     Constructs <see cref="RgbPaletteEntry" />.
    /// </summary>
    /// <param name="r">Red channel sample value</param>
    /// <param name="g">Green channel sample value</param>
    /// <param name="b">Blue channel sample value</param>
    public RgbPaletteEntry(
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
    public ushort R { get; }

    /// <summary>
    ///     Green channel sample value
    /// </summary>
    public ushort G { get; }

    /// <summary>
    ///     Blue channel sample value
    /// </summary>
    public ushort B { get; }
}
