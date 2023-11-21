using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.Cryptography.Sign;

public interface IDigitalSignatureVerifier
{
    bool IsValidCertificateSign(X509Certificate2 certificate, CoseAlgorithm alg, byte[] dataToVerify, byte[] signature);

    bool IsValidCoseKeySign(AbstractCoseKey coseKey, byte[] dataToVerify, byte[] signature);
}
