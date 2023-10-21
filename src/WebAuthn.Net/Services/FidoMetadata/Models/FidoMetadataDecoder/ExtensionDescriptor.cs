namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;

/// <summary>
///     Extension Descriptor
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#extensiondescriptor-dictionary">FIDO Metadata Statement - §3.10. ExtensionDescriptor dictionary</a>
///     </para>
/// </remarks>
public class ExtensionDescriptor
{
    /// <summary>
    ///     Constructs <see cref="ExtensionDescriptor" />.
    /// </summary>
    /// <param name="id">Identifies the extension.</param>
    /// <param name="tag">The TAG of the extension if this was assigned. TAGs are assigned to extensions if they could appear in an assertion.</param>
    /// <param name="data">Contains arbitrary data further describing the extension and/or data needed to correctly process the extension.</param>
    /// <param name="failIfUnknown">
    ///     <para>
    ///         Indicates whether unknown extensions must be ignored (false) or must lead to an error (true) when the extension is to be processed by the FIDO Server, FIDO Client, ASM, or FIDO Authenticator.
    ///         <list type="bullet">
    ///             <item>
    ///                 <description>A value of false indicates that unknown extensions MUST be ignored.</description>
    ///             </item>
    ///             <item>
    ///                 <description>A value of true indicates that unknown extensions MUST result in an error.</description>
    ///             </item>
    ///         </list>
    ///     </para>
    /// </param>
    public ExtensionDescriptor(
        string id,
        ushort? tag,
        string? data,
        bool failIfUnknown)
    {
        Id = id;
        Tag = tag;
        Data = data;
        FailIfUnknown = failIfUnknown;
    }

    /// <summary>
    ///     Identifies the extension.
    /// </summary>
    public string Id { get; }

    /// <summary>
    ///     The TAG of the extension if this was assigned. TAGs are assigned to extensions if they could appear in an assertion.
    /// </summary>
    /// <remarks>
    ///     Examples are TAG_USER_VERIFICATION_STATE and TAG_USER_VERIFICATION_INDEX as defined in <a href="https://fidoalliance.org/specs/fido-uaf-v1.2-ps-20201020/fido-uaf-reg-v1.2-ps-20201020.html">[UAFRegistry]</a>.
    /// </remarks>
    public ushort? Tag { get; }

    /// <summary>
    ///     Contains arbitrary data further describing the extension and/or data needed to correctly process the extension.
    /// </summary>
    public string? Data { get; }

    /// <summary>
    ///     <para>
    ///         Indicates whether unknown extensions must be ignored (false) or must lead to an error (true) when the extension is to be processed by the FIDO Server, FIDO Client, ASM, or FIDO Authenticator.
    ///         <list type="bullet">
    ///             <item>
    ///                 <description>A value of false indicates that unknown extensions MUST be ignored.</description>
    ///             </item>
    ///             <item>
    ///                 <description>A value of true indicates that unknown extensions MUST result in an error.</description>
    ///             </item>
    ///         </list>
    ///     </para>
    /// </summary>
    public bool FailIfUnknown { get; }
}
