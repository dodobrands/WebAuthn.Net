using System;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Enums;

namespace WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree.Abstractions;

public abstract class AbstractCborObject : IEquatable<AbstractCborObject>
{
    public abstract CborType Type { get; }
    public abstract bool Equals(AbstractCborObject? other);
    public abstract override int GetHashCode();

    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is AbstractCborObject cborObject && Equals(cborObject)));
    }

    public static bool operator ==(AbstractCborObject? left, AbstractCborObject? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(AbstractCborObject? left, AbstractCborObject? right)
    {
        return !Equals(left, right);
    }
}
