using System.Formats.Asn1;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

public abstract class AbstractAsn1Enumerable : AbstractAsn1Element
{
    protected AbstractAsn1Enumerable(Asn1Tag tag, AbstractAsn1Element[] items)
    {
        Tag = tag;
        Items = items;
    }

    public override Asn1Tag Tag { get; }

    public AbstractAsn1Element[] Items { get; }
}
