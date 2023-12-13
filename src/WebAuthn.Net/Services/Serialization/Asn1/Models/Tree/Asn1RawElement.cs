using System.Formats.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;

/// <summary>
///     Container for the undecoded RAW ASN.1 element.
/// </summary>
public class Asn1RawElement : AbstractAsn1Element
{
    /// <summary>
    ///     Constructs <see cref="Asn1RawElement" />.
    /// </summary>
    /// <param name="tag">The ASN.1 element tag, described in the ITU-T Recommendation X.680.</param>
    /// <param name="rawValue">Raw value of the ASN.1 element.</param>
    public Asn1RawElement(Asn1Tag tag, byte[] rawValue)
    {
        Tag = tag;
        RawValue = rawValue;
    }

    /// <inheritdoc />
    public override Asn1Tag Tag { get; }

    /// <summary>
    ///     Raw value of the ASN.1 element.
    /// </summary>
    public byte[] RawValue { get; }
}
