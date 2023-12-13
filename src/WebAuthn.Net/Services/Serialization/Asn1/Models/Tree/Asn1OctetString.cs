using System.Formats.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;

/// <summary>
///     Container for the ASN.1 OctetString element (tag assignment: <see cref="UniversalTagNumber.OctetString" />).
/// </summary>
public class Asn1OctetString : AbstractAsn1Element
{
    /// <summary>
    ///     Constructs <see cref="Asn1OctetString" />.
    /// </summary>
    /// <param name="tag">The ASN.1 element tag, described in the ITU-T Recommendation X.680.</param>
    /// <param name="value">The value of OctetString data type (tag assignment: <see cref="UniversalTagNumber.OctetString" />).</param>
    public Asn1OctetString(Asn1Tag tag, byte[] value)
    {
        Tag = tag;
        Value = value;
    }

    /// <inheritdoc />
    public override Asn1Tag Tag { get; }

    /// <summary>
    ///     The value of OctetString data type (tag assignment: <see cref="UniversalTagNumber.OctetString" />).
    /// </summary>
    public byte[] Value { get; }
}
