using System.Security.Cryptography.X509Certificates;

namespace WebAuthn.Net.Services.Static;

public static class X509CertificateInMemoryLoader
{
    public static X509Certificate2 Load(byte[] bytes)
    {
        const X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.EphemeralKeySet;
        const string? password = null;

        return new(bytes, password, keyStorageFlags);
    }
}
