using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus;

/// <summary>
///     Formatter of the serial numbers of certificates in the form that the keys of the <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a>
///     of the Android attestation keys have: lowercase hexadecimal without leading zeros.
/// </summary>
/// <remarks>
///     The certificates are matched with the entries of the status list by their serial numbers in this form only, both when the status list is decoded and when a certificate is looked up in it.
/// </remarks>
public interface IAndroidKeyAttestationStatusSerialNumberFormatter
{
    /// <summary>
    ///     Formats the serial number of a certificate in the form of the keys of the status list.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="serialNumber">If the method returns <see langword="true" />, the serial number in lowercase hexadecimal without leading zeros, otherwise <see langword="null" />.</param>
    /// <returns><see langword="true" /> if the serial number can be in the status list, <see langword="false" /> if it can't (for example, because it is negative).</returns>
    bool TryFormat(X509Certificate2 certificate, [NotNullWhen(true)] out string? serialNumber);

    /// <summary>
    ///     Normalizes a key of the status list: the serial number of a certificate in hexadecimal.
    /// </summary>
    /// <param name="key">The key of an entry of the status list.</param>
    /// <param name="serialNumber">If the method returns <see langword="true" />, the serial number in lowercase hexadecimal without leading zeros, otherwise <see langword="null" />.</param>
    /// <returns><see langword="true" /> if the key is a serial number in hexadecimal (in any case, with or without leading zeros), otherwise <see langword="false" />.</returns>
    bool TryNormalize(string key, [NotNullWhen(true)] out string? serialNumber);
}
