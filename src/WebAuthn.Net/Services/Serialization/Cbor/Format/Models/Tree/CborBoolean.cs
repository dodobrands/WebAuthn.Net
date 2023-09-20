using System;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

public class CborBoolean : AbstractCborObject, IEquatable<CborBoolean>, IEquatable<AbstractCborObject>, IRawValueProvider<bool>
{
    private const CborType ActualType = CborType.Boolean;

    public static readonly CborBoolean True = new(true);
    public static readonly CborBoolean False = new(false);

    public CborBoolean(bool value)
    {
        Value = value;
    }

    public override CborType Type => ActualType;

    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborBoolean otherBoolean && Equals(otherBoolean)));
    }

    public bool Equals(CborBoolean? other)
    {
        return other is not null && (ReferenceEquals(this, other) || Value == other.Value);
    }

    public bool Value { get; }

    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborBoolean otherBoolean && Equals(otherBoolean)));
    }

    public override int GetHashCode()
    {
        return HashCode.Combine((int) ActualType, Value);
    }

    public static bool operator ==(CborBoolean? left, CborBoolean? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(CborBoolean? left, CborBoolean? right)
    {
        return !Equals(left, right);
    }
}
