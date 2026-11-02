using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models;

/// <summary>
///     The <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a> of the Android attestation keys:
///     the certificates that don't have a normal valid status, by their serial numbers.
/// </summary>
public class AndroidKeyAttestationStatusList
{
    /// <summary>
    ///     Constructs <see cref="AndroidKeyAttestationStatusList" />.
    /// </summary>
    /// <param name="entries">The entries of the status list by the serial numbers of their certificates, formatted as <see cref="FormatSerialNumber" /> does it.</param>
    /// <exception cref="ArgumentNullException"><paramref name="entries" /> is <see langword="null" /></exception>
    public AndroidKeyAttestationStatusList(IReadOnlyDictionary<string, AndroidKeyAttestationStatusEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        Entries = entries;
    }

    /// <summary>
    ///     The entries of the status list by the serial numbers of their certificates, formatted as <see cref="FormatSerialNumber" /> does it.
    /// </summary>
    public IReadOnlyDictionary<string, AndroidKeyAttestationStatusEntry> Entries { get; }

    /// <summary>
    ///     Finds the entry of the certificate by its serial number.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <param name="serialNumber">If the certificate is in the status list, its serial number, formatted as <see cref="FormatSerialNumber" /> does it, otherwise <see langword="null" />.</param>
    /// <param name="entry">If the certificate is in the status list, its entry, otherwise <see langword="null" />.</param>
    /// <returns><see langword="true" /> if the certificate is in the status list, otherwise <see langword="false" />.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="certificate" /> is <see langword="null" /></exception>
    public bool TryFindEntry(
        X509Certificate2 certificate,
        [NotNullWhen(true)] out string? serialNumber,
        [NotNullWhen(true)] out AndroidKeyAttestationStatusEntry? entry)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        var key = FormatSerialNumber(certificate.SerialNumberBytes.Span);
        if (key is not null && Entries.TryGetValue(key, out entry))
        {
            serialNumber = key;
            return true;
        }

        serialNumber = null;
        entry = null;
        return false;
    }

    /// <summary>
    ///     Formats the serial number of a certificate as the status list keys its entries: a positive integer in lowercase hexadecimal without leading zeros.
    ///     This is what <c>BigInteger.toString(16)</c> returns for the serial number in Java, and how the <a href="https://github.com/android/keyattestation">verification library of Google</a> looks certificates up in the status list.
    /// </summary>
    /// <param name="serialNumber">The serial number of the certificate: the content octets of its DER INTEGER, big-endian (<see cref="X509Certificate.SerialNumberBytes" />).</param>
    /// <returns>
    ///     The serial number in lowercase hexadecimal without leading zeros, or <see langword="null" /> if it is empty or negative:
    ///     the serial number of a certificate is a positive integer (<a href="https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2">RFC 5280 §4.1.2.2</a>), and so are the keys of the status list.
    /// </returns>
    public static string? FormatSerialNumber(ReadOnlySpan<byte> serialNumber)
    {
        if (serialNumber.IsEmpty || (serialNumber[0] & 0x80) != 0)
        {
            return null;
        }

        var hex = Convert.ToHexStringLower(serialNumber).TrimStart('0');
        return hex.Length > 0 ? hex : "0";
    }
}
