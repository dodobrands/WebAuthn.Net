using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.Serialization.Cose.Models.Enums.RSA;

/// <summary>
///     Valid parameters for a key encoded in RSA format.
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters">IANA COSE Key Type Parameters registry</a>
///     </para>
///     <para>https://www.rfc-editor.org/rfc/rfc8230.html#section-4</para>
/// </remarks>
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum CoseRsaKeyParameter
{
    /// <summary>
    ///     The RSA modulus n
    /// </summary>
    n = -1,

    /// <summary>
    ///     The RSA public exponent e
    /// </summary>
    e = -2
}
