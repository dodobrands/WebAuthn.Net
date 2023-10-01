using System.Formats.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;

public class Asn1Enumerated : AbstractAsn1Element, IValueProvider<byte[]>
{
    public Asn1Enumerated(Asn1Tag tag, byte[] value)
    {
        Tag = tag;
        Value = value;
    }

    public override Asn1Tag Tag { get; }
    public byte[] Value { get; }
}
