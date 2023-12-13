using System.Formats.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;

/// <summary>
///     Container for the ASN.1 Set element (tag assignment: <see cref="UniversalTagNumber.Set" />).
/// </summary>
public class Asn1Set : AbstractAsn1Enumerable
{
    /// <summary>
    ///     Constructs <see cref="Asn1Set" />.
    /// </summary>
    /// <param name="tag">The ASN.1 element tag, described in the ITU-T Recommendation X.680.</param>
    /// <param name="value">Elements contained in the ASN.1 Set (tag assignment: <see cref="UniversalTagNumber.Set" />).</param>
    public Asn1Set(Asn1Tag tag, AbstractAsn1Element[] value) : base(tag, value)
    {
    }
}
