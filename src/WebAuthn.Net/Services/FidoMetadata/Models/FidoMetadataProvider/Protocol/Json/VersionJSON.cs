using System.Text.Json.Serialization;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

/// <summary>
///     Version
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-protocol-v1.2-ps-20201020.html#version-interface">FIDO UAF Protocol Specification - §3.1.1 Version Interface</a>
///     </para>
/// </remarks>
// ReSharper disable once InconsistentNaming
public class VersionJSON
{
    /// <summary>
    ///     Constructs <see cref="VersionJSON" />.
    /// </summary>
    /// <param name="major">Major version.</param>
    /// <param name="minor">Minor version.</param>
    [JsonConstructor]
    public VersionJSON(
        ushort? major,
        ushort? minor)
    {
        Major = major;
        Minor = minor;
    }

    /// <summary>
    ///     Major version.
    /// </summary>
    [JsonPropertyName("major")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ushort? Major { get; }

    /// <summary>
    ///     Minor version.
    /// </summary>
    [JsonPropertyName("minor")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public ushort? Minor { get; }
}
