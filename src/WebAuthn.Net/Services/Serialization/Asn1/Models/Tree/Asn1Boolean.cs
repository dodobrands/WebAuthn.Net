using System.Formats.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;

public class Asn1Boolean : AbstractAsn1Element, IValueProvider<bool>
{
    public Asn1Boolean(Asn1Tag tag, bool value)
    {
        Tag = tag;
        Value = value;
    }

    public override Asn1Tag Tag { get; }

    public bool Value { get; }
}
