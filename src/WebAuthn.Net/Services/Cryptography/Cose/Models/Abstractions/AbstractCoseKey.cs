using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;

namespace WebAuthn.Net.Services.Cryptography.Cose.Models.Abstractions;

public abstract class AbstractCoseKey
{
    public abstract CoseKeyType Kty { get; }
    public abstract CoseAlgorithm Alg { get; }
}
