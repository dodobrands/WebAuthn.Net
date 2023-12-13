using System.Formats.Asn1;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

/// <summary>
///     Abstract enumerable of ASN.1 elements.
/// </summary>
public abstract class AbstractAsn1Enumerable : AbstractAsn1Element
{
    /// <summary>
    ///     Constructs <see cref="AbstractAsn1Enumerable" />.
    /// </summary>
    /// <param name="tag">The ASN.1 element tag, described in the ITU-T Recommendation X.680.</param>
    /// <param name="items">ASN.1 elements of the enumerable.</param>
    protected AbstractAsn1Enumerable(Asn1Tag tag, AbstractAsn1Element[] items)
    {
        Tag = tag;
        Items = items;
    }

    /// <inheritdoc />
    public override Asn1Tag Tag { get; }

    /// <summary>
    ///     ASN.1 elements of the enumerable.
    /// </summary>
    public AbstractAsn1Element[] Items { get; }
}
