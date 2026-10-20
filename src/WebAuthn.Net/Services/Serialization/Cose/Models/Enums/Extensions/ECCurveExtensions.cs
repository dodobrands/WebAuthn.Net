using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2;

namespace WebAuthn.Net.Services.Serialization.Cose.Models.Enums.Extensions;

/// <summary>
///     Extension methods for the built-in .NET type <see cref="ECCurve" />.
/// </summary>
internal static class ECCurveExtensions
{
    /// <summary>
    ///     If possible, converts the built-in .NET type <see cref="ECCurve" /> value to a value of the <see cref="CoseEc2EllipticCurve" /> enum.
    /// </summary>
    /// <param name="ecCurve">The <see cref="ECCurve" /> value that needs to be converted to the <see cref="CoseEc2EllipticCurve" /> enum.</param>
    /// <param name="coseCurve">Output parameter. If the method returns <see langword="true" />, the conversion was successful and it then contains a value from the <see cref="CoseEc2EllipticCurve" /> enum, otherwise - <see langword="null" />.</param>
    /// <returns><see langword="true" />, if the conversion was successful, otherwise - <see langword="false" />.</returns>
    public static bool TryToCoseEc2EllipticCurve(this ECCurve ecCurve, [NotNullWhen(true)] out CoseEc2EllipticCurve? coseCurve)
    {
        // Only the named NIST curves are supported.
        // A key with explicit curve parameters (SpecifiedECDomain, RFC 3279 §2.3.5) does not name its curve: ECCurve.Oid is null unless the curve type is Named,
        // and the platforms differ in whether they map explicit parameters back to a named curve (OpenSSL does so only when they are byte-identical to a known curve, CNG never does).
        if (!ecCurve.IsNamed || ecCurve.Oid is null || string.IsNullOrEmpty(ecCurve.Oid.Value))
        {
            coseCurve = null;
            return false;
        }

        if (ecCurve.Oid.Value.Equals(ECCurve.NamedCurves.nistP256.Oid.Value, StringComparison.Ordinal))
        {
            coseCurve = CoseEc2EllipticCurve.P256;
            return true;
        }

        if (ecCurve.Oid.Value.Equals(ECCurve.NamedCurves.nistP384.Oid.Value, StringComparison.Ordinal))
        {
            coseCurve = CoseEc2EllipticCurve.P384;
            return true;
        }

        if (ecCurve.Oid.Value.Equals(ECCurve.NamedCurves.nistP521.Oid.Value, StringComparison.Ordinal))
        {
            coseCurve = CoseEc2EllipticCurve.P521;
            return true;
        }

        coseCurve = null;
        return false;
    }
}
