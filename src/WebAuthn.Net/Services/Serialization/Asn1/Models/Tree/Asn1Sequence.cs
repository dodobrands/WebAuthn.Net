using System.Formats.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;

/// <summary>
///     Container for the ASN.1 Sequence element (tag assignment: <see cref="UniversalTagNumber.Sequence" />).
/// </summary>
public class Asn1Sequence : AbstractAsn1Enumerable
{
    /// <summary>
    ///     Constructs <see cref="Asn1Sequence" />.
    /// </summary>
    /// <param name="tag">The ASN.1 element tag, described in the ITU-T Recommendation X.680.</param>
    /// <param name="value">Elements contained in the ASN.1 Sequence (tag assignment: <see cref="UniversalTagNumber.Sequence" />).</param>
    public Asn1Sequence(Asn1Tag tag, AbstractAsn1Element[] value) : base(tag, value)
    {
    }
}
