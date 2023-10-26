using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

namespace WebAuthn.Net.Services.Static;

public static class X509CertificateInMemoryLoader
{
    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    public static bool TryLoad(byte[] bytes, [NotNullWhen(true)] out X509Certificate2? certificate)
    {
        const X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.EphemeralKeySet;
        const string? password = null;

        X509Certificate2? cert = null;
        try
        {
            cert = new(bytes, password, keyStorageFlags);
            if (cert.GetRSAPublicKey() is { } rsaPublicKey)
            {
                rsaPublicKey.Dispose();
                certificate = cert;
                return true;
            }

            if (cert.GetECDsaPublicKey() is { } ecDsaPublicKey)
            {
                ecDsaPublicKey.Dispose();
                certificate = cert;
                return true;
            }

            cert.Dispose();
            certificate = null;
            return false;
        }
        catch
        {
            cert?.Dispose();
            certificate = null;
            return false;
        }
    }
}
