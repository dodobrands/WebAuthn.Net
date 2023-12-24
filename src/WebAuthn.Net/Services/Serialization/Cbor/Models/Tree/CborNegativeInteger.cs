using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

/// <summary>
///     Container for the CBOR "negative integer -1-N" (major type 1) data type.
/// </summary>
public class CborNegativeInteger : AbstractCborInteger, IEquatable<CborNegativeInteger>, IEquatable<AbstractCborObject>
{
    /// <summary>
    ///     Constructs <see cref="CborNegativeInteger" />.
    /// </summary>
    /// <param name="value">Negative number ranging from <c>-1</c> to <see cref="int.MinValue" />.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="value" /> is not in the range from <c>-1</c> to <see cref="int.MinValue" />.</exception>
    public CborNegativeInteger(int value)
    {
#if NET6_0
        if (value > 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }
#else
        ArgumentOutOfRangeException.ThrowIfGreaterThan(value, 0, nameof(value));
#endif
        RawValue = (ulong) (-1 - value);
    }

    /// <summary>
    ///     Constructs <see cref="CborNegativeInteger" />.
    /// </summary>
    /// <param name="value">Raw value.</param>
    public CborNegativeInteger(ulong value)
    {
        RawValue = value;
    }

    /// <inheritdoc />
    public override CborType Type => CborType.NegativeInteger;

    /// <inheritdoc />
    public override ulong RawValue { get; }

    /// <inheritdoc />
    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborNegativeInteger otherNegativeInteger && Equals(otherNegativeInteger)));
    }

    /// <inheritdoc />
    public bool Equals(CborNegativeInteger? other)
    {
        return other is not null && (ReferenceEquals(this, other) || RawValue == other.RawValue);
    }

    /// <inheritdoc />
    public override bool TryReadAsInt32([NotNullWhen(true)] out int? value)
    {
        // https://www.rfc-editor.org/rfc/rfc8949.html#section-3.1
        // A negative integer in the range -2^64..-1 inclusive.
        // The value of the item is -1 minus the argument.
        // For example, the integer -500 would be 0b001_11001 (major type 1, additional information 25)
        // followed by the two bytes 0x01f3, which is 499 in decimal.
        if (RawValue > int.MaxValue)
        {
            value = null;
            return false;
        }

        value = -1 - (int) RawValue;
        return true;
    }

    /// <inheritdoc />
    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborNegativeInteger otherNegativeInteger && Equals(otherNegativeInteger)));
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        return HashCode.Combine((int) Type, RawValue);
    }

    /// <summary>
    ///     Indicates whether the values of two specified <see cref="CborNegativeInteger" /> objects are equal.
    /// </summary>
    /// <param name="left">The first object to compare.</param>
    /// <param name="right">The second object to compare.</param>
    /// <returns>><see langword="true" /> if <paramref name="left" /> and <paramref name="right" /> are equal; otherwise, <see langword="false" />.</returns>
    public static bool operator ==(CborNegativeInteger? left, CborNegativeInteger? right)
    {
        return Equals(left, right);
    }

    /// <summary>
    ///     Indicates whether the values of two specified <see cref="CborNegativeInteger" /> objects are not equal.
    /// </summary>
    /// <param name="left">The first object to compare.</param>
    /// <param name="right">The second object to compare.</param>
    /// <returns><see langword="true" /> if <paramref name="left" /> and <paramref name="right" /> are not equal; otherwise, <see langword="false" />.</returns>
    public static bool operator !=(CborNegativeInteger? left, CborNegativeInteger? right)
    {
        return !Equals(left, right);
    }
}
