using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

public class CborUnsignedInteger : AbstractCborInteger, IEquatable<CborUnsignedInteger>, IEquatable<AbstractCborObject>
{
    private const CborType ActualType = CborType.UnsignedInteger;

    public CborUnsignedInteger(ulong value)
    {
        RawValue = value;
    }

    public override CborType Type => ActualType;

    public override ulong RawValue { get; }

    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborUnsignedInteger otherUnsignedInteger && Equals(otherUnsignedInteger)));
    }

    public bool Equals(CborUnsignedInteger? other)
    {
        return other is not null && (ReferenceEquals(this, other) || RawValue == other.RawValue);
    }

    public override bool TryReadAsInt32([NotNullWhen(true)] out int? value)
    {
        if (RawValue < int.MaxValue)
        {
            value = (int) RawValue;
            return true;
        }

        value = null;
        return false;
    }

    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborUnsignedInteger otherUnsignedInteger && Equals(otherUnsignedInteger)));
    }

    public override int GetHashCode()
    {
        return HashCode.Combine((int) ActualType, RawValue);
    }

    public static bool operator ==(CborUnsignedInteger? left, CborUnsignedInteger? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(CborUnsignedInteger? left, CborUnsignedInteger? right)
    {
        return !Equals(left, right);
    }
}
