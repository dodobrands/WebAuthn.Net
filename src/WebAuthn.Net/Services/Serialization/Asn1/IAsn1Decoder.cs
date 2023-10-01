using System.Formats.Asn1;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Asn1.Models;

namespace WebAuthn.Net.Services.Serialization.Asn1;

public interface IAsn1Decoder
{
    Result<Asn1Root> TryDecode(byte[] input, AsnEncodingRules encodingRules);
}
