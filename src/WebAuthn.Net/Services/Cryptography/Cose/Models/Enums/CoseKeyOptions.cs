namespace WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;

/// <summary>
///     Operations for which the key can be used.
/// </summary>
/// <summary>
///     <a href="https://www.rfc-editor.org/rfc/rfc9052.html#x-table-key-ops">Operations for which the key can be used.</a>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.rfc-editor.org/rfc/rfc9052.html#section-7.1">RFC 9052 CBOR Object Signing and Encryption (COSE): Structures and Process - §7.1. COSE Key Common Parameters</a>
///     </para>
/// </remarks>
public enum CoseKeyOptions
{
    /// <summary>
    ///     The key is used to create signatures. Requires private key fields.
    /// </summary>
    Sign = 1,

    /// <summary>
    ///     The key is used for verification of signatures.
    /// </summary>
    Verify = 2,

    /// <summary>
    ///     The key is used for key transport encryption.
    /// </summary>
    Encrypt = 3,

    /// <summary>
    ///     The key is used for key transport decryption. Requires private key fields.
    /// </summary>
    Decrypt = 4,

    /// <summary>
    ///     The key is used for key wrap encryption.
    /// </summary>
    WrapKey = 5,

    /// <summary>
    ///     The key is used for key wrap decryption. Requires private key fields.
    /// </summary>
    UnwrapKey = 6,

    /// <summary>
    ///     The key is used for deriving keys. Requires private key fields.
    /// </summary>
    DeriveKey = 7,

    /// <summary>
    ///     The key is used for deriving bits not to be used as a key. Requires private key fields.
    /// </summary>
    DeriveBits = 8,

    /// <summary>
    ///     The key is used for creating MACs.
    /// </summary>
    MacCreate = 9,

    /// <summary>
    ///     The key is used for validating MACs.
    /// </summary>
    MacVerify = 10
}
