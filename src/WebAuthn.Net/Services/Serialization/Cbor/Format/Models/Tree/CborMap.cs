using System;
using System.Collections.Generic;
using System.Linq;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

public class CborMap : AbstractCborObject, IEquatable<CborMap>, IEquatable<AbstractCborObject>, IRawValueProvider<IReadOnlyDictionary<AbstractCborObject, AbstractCborObject>>
{
    private const CborType ActualType = CborType.Map;
    private readonly Dictionary<AbstractCborObject, AbstractCborObject> _values = new();

    public CborMap()
    {
    }

    public CborMap(IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> values)
    {
        _values = new(values);
    }

    public override CborType Type => ActualType;

    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborMap otherCborMap && Equals(otherCborMap)));
    }

    public bool Equals(CborMap? other)
    {
        return other is not null && (ReferenceEquals(this, other) || _values.OrderBy(x => x.Key).SequenceEqual(other._values.OrderBy(x => x.Key)));
    }

    public IReadOnlyDictionary<AbstractCborObject, AbstractCborObject> Value => _values;

    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborMap otherCborMap && Equals(otherCborMap)));
    }

    public override int GetHashCode()
    {
        var hashCode = (int) ActualType;
        foreach (var (key, value) in _values)
        {
            hashCode = HashCode.Combine(hashCode, key);
            hashCode = HashCode.Combine(hashCode, value);
        }

        return hashCode;
    }

    public static bool operator ==(CborMap? left, CborMap? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(CborMap? left, CborMap? right)
    {
        return !Equals(left, right);
    }
}
