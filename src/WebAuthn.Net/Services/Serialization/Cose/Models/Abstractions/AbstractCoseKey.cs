using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;

public abstract class AbstractCoseKey
{
    public abstract CoseKeyType Kty { get; }
    public abstract CoseAlgorithm Alg { get; }
    public abstract bool Matches(X509Certificate2 certificate);
    public abstract bool Matches(AsymmetricAlgorithm asymmetricAlgorithm);
    public abstract bool Matches(AbstractCoseKey coseKey);
}
