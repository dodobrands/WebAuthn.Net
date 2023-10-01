using System.Formats.Asn1;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

public abstract class AbstractAsn1Element
{
    public abstract Asn1Tag Tag { get; }
}
