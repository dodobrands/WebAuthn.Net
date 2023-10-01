using System.Formats.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;

public class Asn1BitString : AbstractAsn1Element, IValueProvider<Asn1BitStringValue>
{
    public Asn1BitString(Asn1Tag tag, Asn1BitStringValue value)
    {
        Tag = tag;
        Value = value;
    }

    public override Asn1Tag Tag { get; }
    public Asn1BitStringValue Value { get; }
}

public class Asn1BitStringValue
{
    public Asn1BitStringValue(byte[] value, int unusedBitCount)
    {
        Value = value;
        UnusedBitCount = unusedBitCount;
    }

    public byte[] Value { get; }

    public int UnusedBitCount { get; }
}
