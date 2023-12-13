using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

/// <summary>
///     Container for the CBOR "unsigned integer N" (major type 0) data type.
/// </summary>
public class CborUnsignedInteger : AbstractCborInteger, IEquatable<CborUnsignedInteger>, IEquatable<AbstractCborObject>
{
    /// <summary>
    ///     Constructs <see cref="CborUnsignedInteger" />.
    /// </summary>
    /// <param name="value">Raw value.</param>
    public CborUnsignedInteger(ulong value)
    {
        RawValue = value;
    }

    /// <inheritdoc />
    public override CborType Type => CborType.UnsignedInteger;

    /// <inheritdoc />
    public override ulong RawValue { get; }

    /// <inheritdoc />
    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborUnsignedInteger otherUnsignedInteger && Equals(otherUnsignedInteger)));
    }

    /// <inheritdoc />
    public bool Equals(CborUnsignedInteger? other)
    {
        return other is not null && (ReferenceEquals(this, other) || RawValue == other.RawValue);
    }

    /// <inheritdoc />
    public override bool TryReadAsInt32([NotNullWhen(true)] out int? value)
    {
        if (RawValue < int.MaxValue)
        {
            value = (int) RawValue;
            return true;
        }

        value = null;
        return false;
    }

    /// <inheritdoc />
    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborUnsignedInteger otherUnsignedInteger && Equals(otherUnsignedInteger)));
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        return HashCode.Combine((int) Type, RawValue);
    }

    /// <summary>
    ///     Indicates whether the values of two specified <see cref="CborUnsignedInteger" /> objects are equal.
    /// </summary>
    /// <param name="left">The first object to compare.</param>
    /// <param name="right">The second object to compare.</param>
    /// <returns>><see langword="true" /> if <paramref name="left" /> and <paramref name="right" /> are equal; otherwise, <see langword="false" />.</returns>
    public static bool operator ==(CborUnsignedInteger? left, CborUnsignedInteger? right)
    {
        return Equals(left, right);
    }

    /// <summary>
    ///     Indicates whether the values of two specified <see cref="CborUnsignedInteger" /> objects are not equal.
    /// </summary>
    /// <param name="left">The first object to compare.</param>
    /// <param name="right">The second object to compare.</param>
    /// <returns><see langword="true" /> if <paramref name="left" /> and <paramref name="right" /> are not equal; otherwise, <see langword="false" />.</returns>
    public static bool operator !=(CborUnsignedInteger? left, CborUnsignedInteger? right)
    {
        return !Equals(left, right);
    }
}
