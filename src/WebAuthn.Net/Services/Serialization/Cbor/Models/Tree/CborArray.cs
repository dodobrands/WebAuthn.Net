using System;
using System.Collections.Generic;
using System.Linq;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

/// <summary>
///     Container for the CBOR "array" (major type 4) data type.
/// </summary>
public class CborArray : AbstractCborObject, IEquatable<CborArray>, IEquatable<AbstractCborObject>
{
    /// <summary>
    ///     Constructs <see cref="CborArray" />.
    /// </summary>
    public CborArray()
    {
    }

    /// <summary>
    ///     Constructs <see cref="CborArray" />.
    /// </summary>
    /// <param name="values">Array elements.</param>
    public CborArray(IEnumerable<AbstractCborObject> values)
    {
        RawValue = values.ToArray();
    }

    /// <inheritdoc />
    public override CborType Type => CborType.Array;

    /// <summary>
    ///     Raw value.
    /// </summary>
    public AbstractCborObject[] RawValue { get; } = Array.Empty<AbstractCborObject>();

    /// <inheritdoc />
    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborArray otherCborArray && Equals(otherCborArray)));
    }

    /// <inheritdoc />
    public bool Equals(CborArray? other)
    {
        return other is not null && (ReferenceEquals(this, other) || RawValue.SequenceEqual(other.RawValue));
    }

    /// <inheritdoc />
    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborArray otherCborArray && Equals(otherCborArray)));
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
    ///     Indicates whether the values of two specified <see cref="CborArray" /> objects are equal.
    /// </summary>
    /// <param name="left">The first object to compare.</param>
    /// <param name="right">The second object to compare.</param>
    /// <returns>><see langword="true" /> if <paramref name="left" /> and <paramref name="right" /> are equal; otherwise, <see langword="false" />.</returns>
    public static bool operator ==(CborArray? left, CborArray? right)
    {
        return Equals(left, right);
    }

    /// <summary>
    ///     Indicates whether the values of two specified <see cref="CborArray" /> objects are not equal.
    /// </summary>
    /// <param name="left">The first object to compare.</param>
    /// <param name="right">The second object to compare.</param>
    /// <returns><see langword="true" /> if <paramref name="left" /> and <paramref name="right" /> are not equal; otherwise, <see langword="false" />.</returns>
    public static bool operator !=(CborArray? left, CborArray? right)
    {
        return !Equals(left, right);
    }
}
