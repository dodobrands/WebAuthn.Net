using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationObjectDecoder.Models;

namespace WebAuthn.Net.Services.Common.AttestationObjectDecoder.Abstractions;

public interface IAttestationObjectDecoder
{
    Result<AttestationObject> Decode(byte[] attestationObject);
}
