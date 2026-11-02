using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusSerialNumberFormatter;

/// <summary>
///     Default implementation of <see cref="IAndroidKeyAttestationStatusSerialNumberFormatter" />.
/// </summary>
/// <remarks>
///     A serial number is formatted as <c>BigInteger.toString(16)</c> in Java formats a positive integer, which is how the
///     <a href="https://github.com/android/keyattestation">verification library of Google</a> looks certificates up in the status list.
///     The keys of the status list consisting of decimal digits only are hexadecimal too: the serial numbers of factory-provisioned attestation keys often have such hexadecimal digits.
/// </remarks>
public class DefaultAndroidKeyAttestationStatusSerialNumberFormatter : IAndroidKeyAttestationStatusSerialNumberFormatter
{
    /// <inheritdoc />
    public virtual bool TryFormat(X509Certificate2 certificate, [NotNullWhen(true)] out string? serialNumber)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        // the content octets of the DER INTEGER, big-endian two's complement: a positive serial number whose first octet has the high bit set starts with a zero octet
        var octets = certificate.SerialNumberBytes.Span;
        // the serial number of a certificate is a positive integer (https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2), and so are the keys of the status list,
        // so a negative serial number of a non-conforming certificate can't be in it
        if (octets.IsEmpty || (octets[0] & 0x80) != 0)
        {
            serialNumber = null;
            return false;
        }

        serialNumber = TrimLeadingZeros(Convert.ToHexStringLower(octets));
        return true;
    }

    /// <inheritdoc />
    public virtual bool TryNormalize(string key, [NotNullWhen(true)] out string? serialNumber)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length == 0 || !key.All(char.IsAsciiHexDigit))
        {
            serialNumber = null;
            return false;
        }

        serialNumber = TrimLeadingZeros(key.ToLowerInvariant());
        return true;
    }

    private static string TrimLeadingZeros(string hex)
    {
        var result = hex.TrimStart('0');
        return result.Length > 0 ? result : "0";
    }
}
