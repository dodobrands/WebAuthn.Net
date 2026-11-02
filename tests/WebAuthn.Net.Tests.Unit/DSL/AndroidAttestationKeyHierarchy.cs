using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WebAuthn.Net.DSL;

/// <summary>
///     A test stand-in for the hierarchy of the key attestation of Google: a root certificate, an intermediate certificate and the certificate of an Android attestation key.
///     As in the chains of real devices, the certificate of the attestation key is a CA (it issues the certificates of the keys that the device attests), so whoever holds the attestation key
///     (for example, one extracted from a device) can sign any certificate with it. Nobody outside Google can issue a certificate under its real root certificates.
/// </summary>
internal sealed class AndroidAttestationKeyHierarchy : IDisposable
{
    // the serial numbers in the form of the keys of the status list of the Android attestation keys: lowercase hexadecimal without leading zeros
    public const string RootSerialNumber = "51";
    public const string IntermediateSerialNumber = "52";
    public const string AttestationKeySerialNumber = "c35747a084470c3135aeefe2b8d40cd6";
    public const string AttestationCertificateSerialNumber = "54";

    private const string RootSubject = "CN=WebAuthn.Net Test Key Attestation Root";
    private const string IntermediateSubject = "CN=WebAuthn.Net Test Key Attestation Intermediate";
    private const string AttestationKeySubject = "CN=WebAuthn.Net Test Android Attestation Key";

    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    private readonly ECDsa _attestationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public AndroidAttestationKeyHierarchy()
    {
        Root = CreateCertificate(RootSubject, _rootKey, RootSubject, _rootKey, true, RootSerialNumber);
        Intermediate = CreateCertificate(IntermediateSubject, _intermediateKey, RootSubject, _rootKey, true, IntermediateSerialNumber);
        AttestationKeyCertificate = CreateCertificate(AttestationKeySubject, _attestationKey, IntermediateSubject, _intermediateKey, true, AttestationKeySerialNumber);
    }

    public byte[] Root { get; }

    public byte[] Intermediate { get; }

    public byte[] AttestationKeyCertificate { get; }

    public void Dispose()
    {
        _attestationKey.Dispose();
        _intermediateKey.Dispose();
        _rootKey.Dispose();
    }

    // an attestation certificate of a "packed" attestation statement (WebAuthn §8.2.1) for the key, signed with the attestation key
    public byte[] IssuePackedAttestationCertificate(ECDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return CreateCertificate(
            "C=US, O=WebAuthn.Net, OU=Authenticator Attestation, CN=WebAuthn.Net Test Packed Attestation",
            key,
            AttestationKeySubject,
            _attestationKey,
            false,
            AttestationCertificateSerialNumber);
    }

    // another root certificate with the key and the subject of the root certificate, as when a root certificate is issued again
    public byte[] IssueRootAgain(string serialNumber)
    {
        return CreateCertificate(RootSubject, _rootKey, RootSubject, _rootKey, true, serialNumber);
    }

    private static byte[] CreateCertificate(string subject, ECDsa key, string issuerSubject, ECDsa issuerKey, bool isCa, string serialNumber)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCa, false, 0, true));
        if (isCa)
        {
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        }

        using var certificate = request.Create(
            new X500DistinguishedName(issuerSubject),
            X509SignatureGenerator.CreateForECDsa(issuerKey),
            Now.AddDays(-1),
            Now.AddDays(30),
            Convert.FromHexString(serialNumber.Length % 2 == 0 ? serialNumber : "0" + serialNumber));
        return certificate.RawData;
    }
}
