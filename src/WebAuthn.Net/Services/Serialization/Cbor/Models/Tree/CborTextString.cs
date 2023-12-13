using System;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

/// <summary>
///     Container for the CBOR "text string" (major type 3) data type.
/// </summary>
public class CborTextString : AbstractCborObject, IEquatable<CborTextString>, IEquatable<AbstractCborObject>
{
    /// <summary>
    ///     Constructs <see cref="CborTextString" />.
    /// </summary>
    /// <param name="value">Raw value.</param>
    public CborTextString(string value)
    {
        RawValue = value;
    }

    /// <inheritdoc />
    public override CborType Type => CborType.TextString;

    /// <summary>
    ///     Raw value.
    /// </summary>
    public string RawValue { get; }

    /// <inheritdoc />
    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborTextString otherTextString && Equals(otherTextString)));
    }

    /// <inheritdoc />
    public bool Equals(CborTextString? other)
    {
        return other is not null && (ReferenceEquals(this, other) || RawValue == other.RawValue);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborTextString otherTextString && Equals(otherTextString)));
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        return HashCode.Combine((int) Type, RawValue);
    }

    /// <summary>
    ///     Indicates whether the values of two specified <see cref="CborTextString" /> objects are equal.
    /// </summary>
    /// <param name="left">The first object to compare.</param>
    /// <param name="right">The second object to compare.</param>
    /// <returns>><see langword="true" /> if <paramref name="left" /> and <paramref name="right" /> are equal; otherwise, <see langword="false" />.</returns>
    public static bool operator ==(CborTextString? left, CborTextString? right)
    {
        return Equals(left, right);
    }

    /// <summary>
    ///     Indicates whether the values of two specified <see cref="CborTextString" /> objects are not equal.
    /// </summary>
    /// <param name="left">The first object to compare.</param>
    /// <param name="right">The second object to compare.</param>
    /// <returns><see langword="true" /> if <paramref name="left" /> and <paramref name="right" /> are not equal; otherwise, <see langword="false" />.</returns>
    public static bool operator !=(CborTextString? left, CborTextString? right)
    {
        return !Equals(left, right);
    }
}
