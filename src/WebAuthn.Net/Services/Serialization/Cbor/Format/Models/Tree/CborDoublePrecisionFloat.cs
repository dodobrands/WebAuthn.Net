using System;
using System.Runtime.CompilerServices;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

public class CborDoublePrecisionFloat : AbstractCborObject, IEquatable<CborDoublePrecisionFloat>, IEquatable<AbstractCborObject>, IRawValueProvider<double>
{
    private const CborType ActualType = CborType.DoublePrecisionFloat;
    private readonly double _value;

    public CborDoublePrecisionFloat(double value)
    {
        _value = value;
    }

    public override CborType Type => ActualType;

    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborDoublePrecisionFloat otherDoublePrecisionFloat && Equals(otherDoublePrecisionFloat)));
    }

    public bool Equals(CborDoublePrecisionFloat? other)
    {
        if (other is null)
        {
            return false;
        }

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        var selfBits = Unsafe.As<double, long>(ref Unsafe.AsRef(in _value));
        // Optimized check for IsNan() || IsZero()
        if (((selfBits - 1) & 0x7FFFFFFFFFFFFFFF) >= 0x7FF0000000000000)
        {
            // Ensure that all NaNs and both zeros have the same hash code
            selfBits &= 0x7FF0000000000000;
        }

        var otherBits = Unsafe.As<double, long>(ref Unsafe.AsRef(in other._value));
        // Optimized check for IsNan() || IsZero()
        if (((otherBits - 1) & 0x7FFFFFFFFFFFFFFF) >= 0x7FF0000000000000)
        {
            // Ensure that all NaNs and both zeros have the same hash code
            otherBits &= 0x7FF0000000000000;
        }

        return selfBits == otherBits;
    }

    public double Value => _value;

    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborDoublePrecisionFloat otherDoublePrecisionFloat && Equals(otherDoublePrecisionFloat)));
    }

    public override int GetHashCode()
    {
        return HashCode.Combine((int) ActualType, _value);
    }

    public static bool operator ==(CborDoublePrecisionFloat? left, CborDoublePrecisionFloat? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(CborDoublePrecisionFloat? left, CborDoublePrecisionFloat? right)
    {
        return !Equals(left, right);
    }
}
