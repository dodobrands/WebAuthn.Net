using System.Formats.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;

public class Asn1RawElement : AbstractAsn1Element
{
    public Asn1RawElement(Asn1Tag tag, byte[] rawValue)
    {
        Tag = tag;
        RawValue = rawValue;
    }

    public override Asn1Tag Tag { get; }

    public byte[] RawValue { get; }
}
