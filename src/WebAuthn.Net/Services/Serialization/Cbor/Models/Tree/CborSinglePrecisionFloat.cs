using System;
using System.Runtime.CompilerServices;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;

public class CborSinglePrecisionFloat : AbstractCborObject, IEquatable<CborSinglePrecisionFloat>, IEquatable<AbstractCborObject>, IRawValueProvider<float>
{
    private const CborType ActualType = CborType.SinglePrecisionFloat;
    private readonly float _value;

    public CborSinglePrecisionFloat(float value)
    {
        _value = value;
    }

    public override CborType Type => ActualType;

    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborSinglePrecisionFloat otherSinglePrecisionFloat && Equals(otherSinglePrecisionFloat)));
    }

    public bool Equals(CborSinglePrecisionFloat? other)
    {
        if (other is null)
        {
            return false;
        }

        if (ReferenceEquals(this, other))
        {
            return true;
        }

        var selfBits = Unsafe.As<float, int>(ref Unsafe.AsRef(in _value));
        // Optimized check for IsNan() || IsZero()
        if (((selfBits - 1) & 0x7FFFFFFF) >= 0x7F800000)
        {
            // Ensure that all NaNs and both zeros have the same hash code
            selfBits &= 0x7F800000;
        }

        var otherBits = Unsafe.As<float, int>(ref Unsafe.AsRef(in other._value));
        // Optimized check for IsNan() || IsZero()
        if (((otherBits - 1) & 0x7FFFFFFF) >= 0x7F800000)
        {
            // Ensure that all NaNs and both zeros have the same hash code
            otherBits &= 0x7F800000;
        }

        return selfBits == otherBits;
    }

    public float RawValue => _value;

    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborSinglePrecisionFloat otherSinglePrecisionFloat && Equals(otherSinglePrecisionFloat)));
    }

    public override int GetHashCode()
    {
        return HashCode.Combine((int) ActualType, _value);
    }

    public static bool operator ==(CborSinglePrecisionFloat? left, CborSinglePrecisionFloat? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(CborSinglePrecisionFloat? left, CborSinglePrecisionFloat? right)
    {
        return !Equals(left, right);
    }
}
