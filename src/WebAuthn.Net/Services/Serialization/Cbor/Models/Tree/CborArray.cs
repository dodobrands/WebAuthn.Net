using System;
using System.Collections.Generic;
using System.Linq;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

public class CborArray : AbstractCborObject, IEquatable<CborArray>, IEquatable<AbstractCborObject>, IRawValueProvider<AbstractCborObject[]>
{
    private const CborType ActualType = CborType.Array;

    public CborArray()
    {
    }

    public CborArray(IEnumerable<AbstractCborObject> values)
    {
        RawValue = values.ToArray();
    }

    public override CborType Type => ActualType;

    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborArray otherCborArray && Equals(otherCborArray)));
    }

    public bool Equals(CborArray? other)
    {
        return other is not null && (ReferenceEquals(this, other) || RawValue.SequenceEqual(other.RawValue));
    }

    public AbstractCborObject[] RawValue { get; } = Array.Empty<AbstractCborObject>();

    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborArray otherCborArray && Equals(otherCborArray)));
    }

    public override int GetHashCode()
    {
        var hashCode = (int) ActualType;
        foreach (var value in RawValue)
        {
            hashCode = HashCode.Combine(hashCode, value);
        }

        return hashCode;
    }

    public static bool operator ==(CborArray? left, CborArray? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(CborArray? left, CborArray? right)
    {
        return !Equals(left, right);
    }
}
