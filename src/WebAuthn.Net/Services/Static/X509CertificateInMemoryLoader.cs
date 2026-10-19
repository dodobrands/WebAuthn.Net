using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

namespace WebAuthn.Net.Services.Static;

/// <summary>
///     A static utility for loading x509v3 certificates into an EphemeralKeySet.
/// </summary>
public static class X509CertificateInMemoryLoader
{
    /// <summary>
    ///     If possible, loads an x509v3 certificate into an EphemeralKeySet.
    /// </summary>
    /// <param name="bytes">x509v3 certificate in binary format (DER).</param>
    /// <param name="certificate">Output parameter. The x509v3 certificate, materialized into the built-in .NET type <see cref="X509Certificate2" /> if the method returns <see langword="true" />, otherwise - <see langword="null" />.</param>
    /// <returns>
    ///     <see langword="true" /> if it was possible to load the x509v3 certificate into the EphemeralKeySet (materializing it into <see cref="X509Certificate2" />), its validity period, subject and extensions can be read,
    ///     and the loaded certificate has a valid public key (ECDSA or RSA), otherwise - <see langword="false" />.
    /// </returns>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    public static bool TryLoad(byte[] bytes, [NotNullWhen(true)] out X509Certificate2? certificate)
    {
        X509Certificate2? cert = null;
        try
        {
#if NET8_0
            cert = new(bytes, (string?) null, X509KeyStorageFlags.EphemeralKeySet);
#else
            cert = X509CertificateLoader.LoadCertificate(bytes);
#endif
            // Some parts of the certificate are decoded lazily, and the platforms differ in what they validate when loading:
            // on Linux, for example, a certificate whose validity time does not follow RFC 5280 loads, but reading NotBefore / NotAfter throws CryptographicException.
            // They are read here, so that a malformed certificate is rejected by this method instead of throwing later in the code that uses it.
            _ = cert.NotBefore;
            _ = cert.NotAfter;
            _ = cert.SubjectName.RawData;
            _ = cert.Extensions;
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
