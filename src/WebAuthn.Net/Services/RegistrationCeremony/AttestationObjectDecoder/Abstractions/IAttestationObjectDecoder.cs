using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Abstractions;

public interface IAttestationObjectDecoder
{
    Result<DecodedAttestationObject> Decode(byte[] attestationObject);
}
