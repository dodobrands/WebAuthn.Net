using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;

namespace WebAuthn.Net.Services.Cryptography.Cose.Models.Abstractions;

public abstract class AbstractCoseKey
{
    public abstract CoseKeyType Kty { get; }
    public abstract CoseAlgorithm Alg { get; }
    public abstract bool Matches(PublicKey certificatePublicKey);
    public abstract bool Matches(AsymmetricAlgorithm asymmetricAlgorithm);
}
