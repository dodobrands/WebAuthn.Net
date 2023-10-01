using System;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

public class CborUndefined : AbstractCborObject, IEquatable<CborUndefined>, IEquatable<AbstractCborObject>
{
    private const CborType ActualType = CborType.Undefined;

    public static readonly CborUndefined Instance = new();
    public override CborType Type => ActualType;

    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || other is CborUndefined);
    }

    public bool Equals(CborUndefined? other)
    {
        return other is not null;
    }

    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || obj is CborUndefined);
    }

    public override int GetHashCode()
    {
        return (int) ActualType;
    }

    public static bool operator ==(CborUndefined? left, CborUndefined? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(CborUndefined? left, CborUndefined? right)
    {
        return !Equals(left, right);
    }
}
