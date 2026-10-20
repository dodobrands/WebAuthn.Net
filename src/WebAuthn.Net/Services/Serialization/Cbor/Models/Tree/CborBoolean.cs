using System;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

/// <summary>
///     Container for the CBOR "boolean" (major type 7, simple values 20 and 21) data type.
/// </summary>
public class CborBoolean : AbstractCborObject, IEquatable<CborBoolean>, IEquatable<AbstractCborObject>
{
    /// <summary>
    ///     Constructs <see cref="CborBoolean" />.
    /// </summary>
    /// <param name="value">Raw value.</param>
    public CborBoolean(bool value)
    {
        RawValue = value;
    }

    /// <inheritdoc />
    public override CborType Type => CborType.Boolean;

    /// <summary>
    ///     Raw value.
    /// </summary>
    public bool RawValue { get; }

    /// <inheritdoc />
    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborBoolean otherBoolean && Equals(otherBoolean)));
    }

    /// <inheritdoc />
    public bool Equals(CborBoolean? other)
    {
        return other is not null && (ReferenceEquals(this, other) || RawValue == other.RawValue);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborBoolean otherBoolean && Equals(otherBoolean)));
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        return HashCode.Combine((int) Type, RawValue);
    }

    /// <summary>
    ///     Indicates whether the values of two specified <see cref="CborBoolean" /> objects are equal.
    /// </summary>
    /// <param name="left">The first object to compare.</param>
    /// <param name="right">The second object to compare.</param>
    /// <returns>><see langword="true" /> if <paramref name="left" /> and <paramref name="right" /> are equal; otherwise, <see langword="false" />.</returns>
    public static bool operator ==(CborBoolean? left, CborBoolean? right)
    {
        return Equals(left, right);
    }

    /// <summary>
    ///     Indicates whether the values of two specified <see cref="CborBoolean" /> objects are not equal.
    /// </summary>
    /// <param name="left">The first object to compare.</param>
    /// <param name="right">The second object to compare.</param>
    /// <returns><see langword="true" /> if <paramref name="left" /> and <paramref name="right" /> are not equal; otherwise, <see langword="false" />.</returns>
    public static bool operator !=(CborBoolean? left, CborBoolean? right)
    {
        return !Equals(left, right);
    }
}
