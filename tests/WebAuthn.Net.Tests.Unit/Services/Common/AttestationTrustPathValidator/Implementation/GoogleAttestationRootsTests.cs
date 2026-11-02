using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using WebAuthn.Net.Services.Common.AttestationTrustPathValidator.Implementation.Constants;

namespace WebAuthn.Net.Services.Common.AttestationTrustPathValidator.Implementation;

// The root certificates of the key attestation of Google embedded in the library are the ones that Google publishes:
// https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate (the current ones and the previously issued ones).
// The Android Key test vector of DefaultRegistrationCeremonyServiceAndroidKeyTests, produced on a real device, chains up to one of them.
public class GoogleAttestationRootsTests
{
    // SHA-256 of the certificates
    private static readonly string[] GoogleRootsSha256 =
    {
        // serialNumber=f92009e853b6b045, valid until 2042-03-15
        "CEDB1CB6DC896AE5EC797348BCE9286753C2B38EE71CE0FBE34A9A1248800DFC",
        // C=US, O=Google LLC, OU=Android, CN=Key Attestation CA1, valid until 2035-07-15, signs attestation certificate chains since 2026-02-01
        "6D9DB4CE6C5C0B293166D08986E05774A8776CEB525D9E4329520DE12BA4BCC0",
        // serialNumber=f92009e853b6b045, valid until 2026-05-24
        "C1984A3EF45C1E2A918551DE10603C86F7051B2249C4891CAE3230EABD0C97D5",
        // serialNumber=f92009e853b6b045, valid until 2034-11-18
        "1EF1A04B8BA58AB94589AC498C8982A783F24EA7307E0159A0C3A73B377D87CC",
        // serialNumber=f92009e853b6b045, valid until 2036-11-13
        "AB6641178A36E179AA0C1CDDDF9A16EB45FA20943E2B8CD7C7C05C26CF8B487A"
    };

    [Test]
    public void Certificates_AreTheRootCertificatesThatGooglePublishes()
    {
        var fingerprints = GoogleAttestationRoots.Certificates.Select(static x => Convert.ToHexString(SHA256.HashData(x))).ToArray();

        Assert.That(fingerprints, Is.EquivalentTo(GoogleRootsSha256));
    }

    [Test]
    public void Certificates_HaveTwoKeys()
    {
        // the root certificates with the subject serialNumber=f92009e853b6b045 are issued for the same key, the Google Hardware Attestation Root key
        var keys = GoogleAttestationRoots.Certificates
            .Select(static x =>
            {
                using var certificate = X509CertificateLoader.LoadCertificate(x);
                return Convert.ToHexString(certificate.PublicKey.ExportSubjectPublicKeyInfo());
            })
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        Assert.That(keys, Has.Length.EqualTo(2));
    }
}
