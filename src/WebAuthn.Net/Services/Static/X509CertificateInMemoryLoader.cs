using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

namespace WebAuthn.Net.Services.Static;

/// <summary>
///     A static utility for loading x509v3 certificates in memory.
/// </summary>
public static class X509CertificateInMemoryLoader
{
    /// <summary>
    ///     If possible, loads an x509v3 certificate in memory.
    /// </summary>
    /// <param name="bytes">x509v3 certificate in binary format (DER).</param>
    /// <param name="certificate">Output parameter. The x509v3 certificate, materialized into the built-in .NET type <see cref="X509Certificate2" /> if the method returns <see langword="true" />, otherwise - <see langword="null" />.</param>
    /// <returns>
    ///     <see langword="true" /> if it was possible to load the x509v3 certificate (materializing it into <see cref="X509Certificate2" />), its validity period, subject and extensions can be read,
    ///     and the loaded certificate has a valid public key (ECDSA or RSA), otherwise - <see langword="false" />.
    /// </returns>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    public static bool TryLoad(byte[] bytes, [NotNullWhen(true)] out X509Certificate2? certificate)
    {
        X509Certificate2? cert = null;
        try
        {
            // Only a single X.509 certificate is acceptable here: loading a PKCS#12 container supplied by a client would run its key-derivation function
            // (with an attacker-chosen iteration count) before anything is verified. X509CertificateLoader.LoadCertificate rejects PKCS#12 (PFX) and PKCS#7 containers.
            cert = X509CertificateLoader.LoadCertificate(bytes);
            // Some parts of the certificate are decoded lazily, and the platforms differ in what they validate when loading:
            // on Linux, for example, a certificate whose validity time does not follow RFC 5280 loads, but reading NotBefore / NotAfter throws CryptographicException.
            // They are read here, so that a malformed certificate is rejected by this method instead of throwing later in the code that uses it.
            _ = cert.NotBefore;
            _ = cert.NotAfter;
            _ = cert.SubjectName.RawData;
            DecodeTypedExtensions(cert);
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

    /// <summary>
    ///     Forces the decoding of the extensions that .NET materializes as typed <see cref="X509Extension" /> subclasses, so that a malformed extension value throws here (and is turned into a <see langword="false" /> result by the caller)
    ///     and not when a property of the extension is read later by the code that uses the certificate.
    /// </summary>
    /// <param name="cert">The loaded certificate.</param>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The value of one of the typed extensions is malformed.</exception>
    private static void DecodeTypedExtensions(X509Certificate2 cert)
    {
        // The platforms do not validate the extension values when loading a certificate (OpenSSL, for example, accepts any value), and the typed extensions created by X509Certificate2.Extensions
        // decode their value on the first property access, throwing CryptographicException for a malformed value. The properties are read here, so that a certificate with a malformed
        // Basic Constraints, Key Usage, Extended Key Usage, Subject Key Identifier or Authority Key Identifier extension is rejected by TryLoad.
        // The Subject Alternative Name extension is deliberately not decoded here: the TPM attestation statement verifier parses it itself and tolerates the layout of the certificate example
        // of the TCG EK Credential Profile (a bare RDNSequence instead of GeneralNames), which the .NET decoder rejects.
        foreach (var extension in cert.Extensions)
        {
            switch (extension)
            {
                case X509BasicConstraintsExtension basicConstraints:
                    _ = basicConstraints.CertificateAuthority;
                    break;
                case X509KeyUsageExtension keyUsage:
                    _ = keyUsage.KeyUsages;
                    break;
                case X509EnhancedKeyUsageExtension enhancedKeyUsage:
                    _ = enhancedKeyUsage.EnhancedKeyUsages;
                    break;
                case X509SubjectKeyIdentifierExtension subjectKeyIdentifier:
                    _ = subjectKeyIdentifier.SubjectKeyIdentifierBytes;
                    break;
                case X509AuthorityKeyIdentifierExtension authorityKeyIdentifier:
                    _ = authorityKeyIdentifier.KeyIdentifier;
                    break;
            }
        }
    }
}
