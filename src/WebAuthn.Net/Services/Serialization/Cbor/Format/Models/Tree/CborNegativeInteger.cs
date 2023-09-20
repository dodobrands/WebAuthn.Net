using System;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

public class CborNegativeInteger : AbstractCborObject, IEquatable<CborNegativeInteger>, IEquatable<AbstractCborObject>, IRawValueProvider<ulong>
{
    private const CborType ActualType = CborType.NegativeInteger;

    public CborNegativeInteger(ulong value)
    {
        Value = value;
    }

    public override CborType Type => ActualType;

    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborNegativeInteger otherNegativeInteger && Equals(otherNegativeInteger)));
    }

    public bool Equals(CborNegativeInteger? other)
    {
        return other is not null && (ReferenceEquals(this, other) || Value == other.Value);
    }

    public ulong Value { get; }

    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborNegativeInteger otherNegativeInteger && Equals(otherNegativeInteger)));
    }

    public override int GetHashCode()
    {
        return HashCode.Combine((int) ActualType, Value);
    }

    public static bool operator ==(CborNegativeInteger? left, CborNegativeInteger? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(CborNegativeInteger? left, CborNegativeInteger? right)
    {
        return !Equals(left, right);
    }
}
