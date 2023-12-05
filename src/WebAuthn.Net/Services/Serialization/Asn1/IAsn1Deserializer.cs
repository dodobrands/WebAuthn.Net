using System.Formats.Asn1;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Serialization.Asn1.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Asn1;

/// <summary>
///     ASN.1 format deserializer.
/// </summary>
public interface IAsn1Deserializer
{
    /// <summary>
    ///     Deserializes ASN.1 into a tree and returns a result containing its root.
    /// </summary>
    /// <param name="input">An array of bytes containing a structure encoded in ASN.1 format.</param>
    /// <param name="encodingRules">The encoding ruleset for an <see cref="AsnReader" />.</param>
    /// <returns>If the deserialization was successful, the result contains an <see cref="AbstractAsn1Element" /> or <see langword="null" />, otherwise the result indicates that an error occurred during deserialization.</returns>
    Result<AbstractAsn1Element?> Deserialize(byte[] input, AsnEncodingRules encodingRules);
}
