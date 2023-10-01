using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Enums;

/// <summary>
///     Data types used when decoding values encoded in CBOR.
/// </summary>
[SuppressMessage("Design", "CA1027:Mark enums with FlagsAttribute")]
[SuppressMessage("Naming", "CA1720:Identifier contains type name")]
public enum CborType
{
    /// <summary>
    ///     Indicates that the CBOR object type is an unsigned integer (major type 0).
    /// </summary>
    UnsignedInteger,

    /// <summary>
    ///     Indicates that the CBOR object type is a negative integer (major type 1).
    /// </summary>
    NegativeInteger,

    /// <summary>
    ///     Indicates that the CBOR object type is a byte string (major type 2).
    /// </summary>
    ByteString,

    /// <summary>
    ///     Indicates that the CBOR object type is a UTF-8 string (major type 3).
    /// </summary>
    TextString,

    /// <summary>
    ///     Indicates that the CBOR object type is an array (major type 4).
    /// </summary>
    Array,

    /// <summary>
    ///     Indicates that the CBOR object type is a map (major type 5).
    /// </summary>
    Map,

    /// <summary>
    ///     Indicates that the CBOR object type is an IEEE 754 Half-Precision float (major type 7).
    /// </summary>
    HalfPrecisionFloat,

    /// <summary>
    ///     Indicates that the CBOR object type is an IEEE 754 Single-Precision float (major type 7).
    /// </summary>
    SinglePrecisionFloat,

    /// <summary>
    ///     Indicates that the CBOR object type is an IEEE 754 Double-Precision float (major type 7).
    /// </summary>
    DoublePrecisionFloat,

    /// <summary>
    ///     Indicates that the CBOR object type is a <see langword="null" /> literal (major type 7).
    /// </summary>
    Null,

    /// <summary>
    ///     Indicates that the CBOR object encodes a <see cref="bool" /> value (major type 7).
    /// </summary>
    Boolean,

    /// <summary>
    ///     Indicates that the CBOR object encodes an undefined value (major type 7).
    /// </summary>
    Undefined
}
