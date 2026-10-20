using System;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

/// <summary>
///     Container for the CBOR "null" (major type 7, simple value 22) data type.
/// </summary>
public class CborNull : AbstractCborObject, IEquatable<CborNull>, IEquatable<AbstractCborObject>
{
    /// <inheritdoc />
    public override CborType Type => CborType.Null;

    /// <inheritdoc />
    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborNull otherNull && Equals(otherNull)));
    }

    /// <inheritdoc />
    public bool Equals(CborNull? other)
    {
        // every CBOR null is the same value
        return other is not null;
    }

    /// <inheritdoc />
    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborNull otherNull && Equals(otherNull)));
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        return HashCode.Combine((int) Type);
    }

    /// <summary>
    ///     Indicates whether the values of two specified <see cref="CborNull" /> objects are equal.
    /// </summary>
    /// <param name="left">The first object to compare.</param>
    /// <param name="right">The second object to compare.</param>
    /// <returns>><see langword="true" /> if <paramref name="left" /> and <paramref name="right" /> are equal; otherwise, <see langword="false" />.</returns>
    public static bool operator ==(CborNull? left, CborNull? right)
    {
        return Equals(left, right);
    }

    /// <summary>
    ///     Indicates whether the values of two specified <see cref="CborNull" /> objects are not equal.
    /// </summary>
    /// <param name="left">The first object to compare.</param>
    /// <param name="right">The second object to compare.</param>
    /// <returns><see langword="true" /> if <paramref name="left" /> and <paramref name="right" /> are not equal; otherwise, <see langword="false" />.</returns>
    public static bool operator !=(CborNull? left, CborNull? right)
    {
        return !Equals(left, right);
    }
}
