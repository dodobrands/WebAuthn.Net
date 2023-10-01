using System.Formats.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;

public class Asn1Sequence : AbstractAsn1Element, IValueProvider<AbstractAsn1Element[]>
{
    public Asn1Sequence(Asn1Tag tag, AbstractAsn1Element[] value)
    {
        Tag = tag;
        Value = value;
    }

    public override Asn1Tag Tag { get; }
    public AbstractAsn1Element[] Value { get; }
}
