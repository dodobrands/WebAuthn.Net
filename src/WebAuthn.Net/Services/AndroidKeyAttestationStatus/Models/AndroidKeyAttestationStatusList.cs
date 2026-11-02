using System;
using System.Collections.Generic;

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
    /// <param name="entries">The entries of the status list by the serial numbers of their certificates in lowercase hexadecimal without leading zeros (see <see cref="IAndroidKeyAttestationStatusSerialNumberFormatter" />).</param>
    /// <exception cref="ArgumentNullException"><paramref name="entries" /> is <see langword="null" /></exception>
    public AndroidKeyAttestationStatusList(IReadOnlyDictionary<string, AndroidKeyAttestationStatusEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        Entries = entries;
    }

    /// <summary>
    ///     The entries of the status list by the serial numbers of their certificates in lowercase hexadecimal without leading zeros (see <see cref="IAndroidKeyAttestationStatusSerialNumberFormatter" />).
    /// </summary>
    public IReadOnlyDictionary<string, AndroidKeyAttestationStatusEntry> Entries { get; }
}
