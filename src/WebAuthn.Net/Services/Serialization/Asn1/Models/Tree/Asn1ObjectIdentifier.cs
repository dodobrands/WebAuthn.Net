using System.Formats.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;

/// <summary>
///     Container for the ASN.1 ObjectIdentifier element (tag assignment: <see cref="UniversalTagNumber.ObjectIdentifier" />).
/// </summary>
public class Asn1ObjectIdentifier : AbstractAsn1Element
{
    /// <summary>
    ///     Constructs <see cref="Asn1ObjectIdentifier" />.
    /// </summary>
    /// <param name="tag">The ASN.1 element tag, described in the ITU-T Recommendation X.680.</param>
    /// <param name="value">The value of ObjectIdentifier data type (tag assignment: <see cref="UniversalTagNumber.ObjectIdentifier" />).</param>
    public Asn1ObjectIdentifier(Asn1Tag tag, string value)
    {
        Tag = tag;
        Value = value;
    }

    /// <inheritdoc />
    public override Asn1Tag Tag { get; }

    /// <summary>
    ///     The value of ObjectIdentifier data type (tag assignment: <see cref="UniversalTagNumber.ObjectIdentifier" />).
    /// </summary>
    public string Value { get; }
}
