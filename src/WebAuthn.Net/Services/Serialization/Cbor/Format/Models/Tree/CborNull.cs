using System;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

public class CborNull : AbstractCborObject, IEquatable<CborNull>, IEquatable<AbstractCborObject>
{
    private const CborType ActualType = CborType.Null;

    public static readonly CborNull Instance = new();
    public override CborType Type => ActualType;

    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || other is CborNull);
    }

    public bool Equals(CborNull? other)
    {
        return other is not null;
    }

    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || obj is CborNull);
    }

    public override int GetHashCode()
    {
        return (int) ActualType;
    }

    public static bool operator ==(CborNull? left, CborNull? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(CborNull? left, CborNull? right)
    {
        return !Equals(left, right);
    }
}
