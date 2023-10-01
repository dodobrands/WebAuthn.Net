using System.Formats.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree;

public class Asn1Set : AbstractAsn1Enumerable
{
    public Asn1Set(Asn1Tag tag, AbstractAsn1Element[] inner) : base(tag, inner)
    {
    }
}
