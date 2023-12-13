using System.Formats.Asn1;

namespace WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

/// <summary>
///     Abstract ASN.1 element.
/// </summary>
public abstract class AbstractAsn1Element
{
    /// <summary>
    ///     The ASN.1 element tag, described in the ITU-T Recommendation X.680.
    /// </summary>
    public abstract Asn1Tag Tag { get; }
}
