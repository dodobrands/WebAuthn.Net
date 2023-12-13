using System.Formats.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;

/// <summary>
///     Container for the ASN.1 UTF8String element (tag assignment: <see cref="UniversalTagNumber.UTF8String" />).
/// </summary>
public class Asn1Utf8String : AbstractAsn1Element
{
    /// <summary>
    ///     Constructs <see cref="Asn1Utf8String" />.
    /// </summary>
    /// <param name="tag">The ASN.1 element tag, described in the ITU-T Recommendation X.680.</param>
    /// <param name="value">The value of UTF8String data type (tag assignment: <see cref="UniversalTagNumber.UTF8String" />).</param>
    public Asn1Utf8String(Asn1Tag tag, string value)
    {
        Tag = tag;
        Value = value;
    }

    /// <inheritdoc />
    public override Asn1Tag Tag { get; }

    /// <summary>
    ///     The value of UTF8String data type (tag assignment: <see cref="UniversalTagNumber.UTF8String" />).
    /// </summary>
    public string Value { get; }
}
