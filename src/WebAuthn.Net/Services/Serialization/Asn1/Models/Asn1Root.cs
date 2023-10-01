using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models;

public class Asn1Root
{
    public Asn1Root(Optional<AbstractAsn1Element> asnRoot)
    {
        AsnRoot = asnRoot;
    }

    public Optional<AbstractAsn1Element> AsnRoot { get; }
}
