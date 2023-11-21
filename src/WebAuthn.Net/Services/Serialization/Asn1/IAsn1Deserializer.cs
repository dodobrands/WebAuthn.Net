using System.Formats.Asn1;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1;

public interface IAsn1Deserializer
{
    Result<Optional<AbstractAsn1Element>> Deserialize(byte[] input, AsnEncodingRules encodingRules);
}
