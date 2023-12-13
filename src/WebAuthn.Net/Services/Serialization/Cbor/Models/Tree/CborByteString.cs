using System;
using System.Linq;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

/// <summary>
///     Container for the CBOR "byte string" (major type 2) data type.
/// </summary>
public class CborByteString : AbstractCborObject, IEquatable<CborByteString>, IEquatable<AbstractCborObject>
{
    /// <summary>
    ///     Constructs <see cref="CborByteString" />.
    /// </summary>
    public CborByteString()
    {
    }

    /// <summary>
    ///     Constructs <see cref="CborByteString" />.
    /// </summary>
    /// <param name="values">Raw value.</param>
    public CborByteString(byte[] values)
    {
        RawValue = values;
    }

    /// <inheritdoc />
    public override CborType Type => CborType.ByteString;

    /// <summary>
    ///     Raw value.
    /// </summary>
    public byte[] RawValue { get; } = Array.Empty<byte>();

    /// <inheritdoc />
    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborByteString otherByteString && Equals(otherByteString)));
    }

    /// <inheritdoc />
    public bool Equals(CborByteString? other)
    {
        return other is not null && (ReferenceEquals(this, other) || RawValue.SequenceEqual(other.RawValue));
    }

    /// <inheritdoc />
    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborByteString otherByteString && Equals(otherByteString)));
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        var hashCode = (int) Type;
        foreach (var value in RawValue)
        {
            hashCode = HashCode.Combine(hashCode, value);
        }

        return hashCode;
    }

    /// <summary>
    ///     Indicates whether the values of two specified <see cref="CborByteString" /> objects are equal.
    /// </summary>
    /// <param name="left">The first object to compare.</param>
    /// <param name="right">The second object to compare.</param>
    /// <returns>><see langword="true" /> if <paramref name="left" /> and <paramref name="right" /> are equal; otherwise, <see langword="false" />.</returns>
    public static bool operator ==(CborByteString? left, CborByteString? right)
    {
        return Equals(left, right);
    }

    /// <summary>
    ///     Indicates whether the values of two specified <see cref="CborByteString" /> objects are not equal.
    /// </summary>
    /// <param name="left">The first object to compare.</param>
    /// <param name="right">The second object to compare.</param>
    /// <returns><see langword="true" /> if <paramref name="left" /> and <paramref name="right" /> are not equal; otherwise, <see langword="false" />.</returns>
    public static bool operator !=(CborByteString? left, CborByteString? right)
    {
        return !Equals(left, right);
    }
}
