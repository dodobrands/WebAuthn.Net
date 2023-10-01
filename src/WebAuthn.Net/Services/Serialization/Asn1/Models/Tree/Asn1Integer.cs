using System.Formats.Asn1;
using System.Numerics;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;

public class Asn1Integer : AbstractAsn1Element, IValueProvider<BigInteger>
{
    public Asn1Integer(Asn1Tag tag, BigInteger value)
    {
        Tag = tag;
        Value = value;
    }

    public override Asn1Tag Tag { get; }

    public BigInteger Value { get; }
}
