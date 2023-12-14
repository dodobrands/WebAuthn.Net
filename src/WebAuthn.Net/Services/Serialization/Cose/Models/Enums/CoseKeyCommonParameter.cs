using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

/// <summary>
///     <a href="https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters">COSE Key Common Parameters</a>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.rfc-editor.org/rfc/rfc9052.html#section-7.1">RFC 9052 CBOR Object Signing and Encryption (COSE): Structures and Process - §7.1. COSE Key Common Parameters</a>
///     </para>
/// </remarks>
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum CoseKeyCommonParameter
{
    /// <summary>
    ///     Required. This parameter is used to identify the family of keys for this structure and, thus, the set of key-type-specific parameters to be found.
    ///     This parameter MUST be present in a key object. Implementations MUST verify that the key type is appropriate for the algorithm being processed.
    ///     The key type MUST be included as part of the trust-decision process.
    /// </summary>
    kty = 1,

    /// <summary>
    ///     Optional. This parameter is used to give an identifier for a key. The identifier is not structured and can be anything
    ///     from a user-provided byte string to a value computed on the public portion of the key.
    ///     This field is intended for matching against a "kid" parameter in a message in order to filter down the set of keys that need to be checked.
    ///     The value of the identifier is not a unique value and can occur in other key objects, even for different keys.
    /// </summary>
    kid = 2,

    /// <summary>
    ///     Optional. This parameter is used to restrict the algorithm that is used with the key.
    ///     If this parameter is present in the key structure, the application must verify
    ///     that this algorithm matches the algorithm for which the key is being used.
    ///     If the algorithms do not match, then this key object MUST NOT be used to perform the cryptographic operation.
    /// </summary>
    /// <remarks>
    ///     Note that the same key can be in a different key structure with a different or no algorithm specified;
    ///     however, this is considered to be a poor security practice.
    /// </remarks>
    alg = 3,

    /// <summary>
    ///     Optional. This parameter is defined to restrict the set of operations that a key is to be used for.
    /// </summary>
    key_ops = 4
}
