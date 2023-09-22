using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

public class CborNegativeInteger : AbstractCborInteger, IEquatable<CborNegativeInteger>, IEquatable<AbstractCborObject>
{
    private const CborType ActualType = CborType.NegativeInteger;

    public CborNegativeInteger(int value)
    {
        if (value > 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value));
        }

        RawValue = (ulong) (-1 - value);
    }

    public CborNegativeInteger(ulong value)
    {
        RawValue = value;
    }

    public override CborType Type => ActualType;

    public override ulong RawValue { get; }

    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborNegativeInteger otherNegativeInteger && Equals(otherNegativeInteger)));
    }

    public bool Equals(CborNegativeInteger? other)
    {
        return other is not null && (ReferenceEquals(this, other) || RawValue == other.RawValue);
    }

    public override bool TryReadAsInt32([NotNullWhen(true)] out int? value)
    {
        if (RawValue > int.MaxValue)
        {
            value = null;
            return false;
        }

        // https://www.rfc-editor.org/rfc/rfc8949.html#section-3.1
        // A negative integer in the range -2^64..-1 inclusive.
        // The value of the item is -1 minus the argument.
        // For example, the integer -500 would be 0b001_11001 (major type 1, additional information 25)
        // followed by the two bytes 0x01f3, which is 499 in decimal.
        var negativeIntArgument = (int) RawValue;
        var realValue = -1 - negativeIntArgument;
        value = realValue;
        return true;
    }

    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborNegativeInteger otherNegativeInteger && Equals(otherNegativeInteger)));
    }

    public override int GetHashCode()
    {
        return HashCode.Combine((int) ActualType, RawValue);
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
