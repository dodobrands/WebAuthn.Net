using System;
using System.Collections.Generic;
using System.Linq;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

/// <summary>
///     Container for the CBOR "map" (major type 5) data type.
/// </summary>
public class CborMap : AbstractCborObject, IEquatable<CborMap>, IEquatable<AbstractCborObject>
{
    private readonly Dictionary<AbstractCborObject, AbstractCborObject> _values = new();

    /// <summary>
    ///     Constructs <see cref="CborMap" />.
    /// </summary>
    public CborMap()
    {
    }

    /// <summary>
    ///     Constructs <see cref="CborMap" />.
    /// </summary>
    /// <param name="values">Map elements</param>
    public CborMap(IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> values)
    {
        _values = new(values);
    }

    /// <inheritdoc />
    public override CborType Type => CborType.Map;

    /// <summary>
    ///     Raw value.
    /// </summary>
    public IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> RawValue => _values;

    /// <inheritdoc />
    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborMap otherCborMap && Equals(otherCborMap)));
    }

    /// <inheritdoc />
    public bool Equals(CborMap? other)
    {
        return other is not null && (ReferenceEquals(this, other) || _values.OrderBy(x => x.Key).SequenceEqual(other._values.OrderBy(x => x.Key)));
    }

    /// <inheritdoc />
    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborMap otherCborMap && Equals(otherCborMap)));
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        var hashCode = (int) Type;
        foreach (var (key, value) in _values)
        {
            hashCode = HashCode.Combine(hashCode, key);
            hashCode = HashCode.Combine(hashCode, value);
        }

        return hashCode;
    }

    /// <summary>
    ///     Indicates whether the values of two specified <see cref="CborMap" /> objects are equal.
    /// </summary>
    /// <param name="left">The first object to compare.</param>
    /// <param name="right">The second object to compare.</param>
    /// <returns>><see langword="true" /> if <paramref name="left" /> and <paramref name="right" /> are equal; otherwise, <see langword="false" />.</returns>
    public static bool operator ==(CborMap? left, CborMap? right)
    {
        return Equals(left, right);
    }

    /// <summary>
    ///     Indicates whether the values of two specified <see cref="CborMap" /> objects are not equal.
    /// </summary>
    /// <param name="left">The first object to compare.</param>
    /// <param name="right">The second object to compare.</param>
    /// <returns><see langword="true" /> if <paramref name="left" /> and <paramref name="right" /> are not equal; otherwise, <see langword="false" />.</returns>
    public static bool operator !=(CborMap? left, CborMap? right)
    {
        return !Equals(left, right);
    }
}
