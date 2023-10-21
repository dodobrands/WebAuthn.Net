namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

/// <summary>
///     Version
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#version-interface">FIDO UAF Protocol Specification - §3.1.1 Version Interface</a>
///     </para>
/// </remarks>
public class Version
{
    /// <summary>
    ///     Constructs <see cref="Version" />.
    /// </summary>
    /// <param name="major">Major version.</param>
    /// <param name="minor">Minor version.</param>
    public Version(ushort? major, ushort? minor)
    {
        Major = major;
        Minor = minor;
    }

    /// <summary>
    ///     Major version.
    /// </summary>
    public ushort? Major { get; }

    /// <summary>
    ///     Minor version.
    /// </summary>
    public ushort? Minor { get; }
}
