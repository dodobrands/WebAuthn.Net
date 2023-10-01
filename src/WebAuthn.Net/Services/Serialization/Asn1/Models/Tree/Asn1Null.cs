using System.Formats.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;

public class Asn1Null : AbstractAsn1Element
{
    public Asn1Null(Asn1Tag tag)
    {
        Tag = tag;
    }

    public override Asn1Tag Tag { get; }
}
