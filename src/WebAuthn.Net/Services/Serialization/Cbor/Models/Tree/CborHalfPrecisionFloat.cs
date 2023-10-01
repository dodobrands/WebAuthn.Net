﻿using System;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

public class CborHalfPrecisionFloat : AbstractCborObject, IEquatable<CborHalfPrecisionFloat>, IEquatable<AbstractCborObject>, IRawValueProvider<Half>
{
    private const CborType ActualType = CborType.HalfPrecisionFloat;

    public CborHalfPrecisionFloat(Half value)
    {
        RawValue = value;
    }

    public override CborType Type => ActualType;

    public override bool Equals(AbstractCborObject? other)
    {
        return other is not null && (ReferenceEquals(this, other) || (other is CborHalfPrecisionFloat otherHalfPrecisionFloat && Equals(otherHalfPrecisionFloat)));
    }

    public bool Equals(CborHalfPrecisionFloat? other)
    {
        return other is not null && (ReferenceEquals(this, other) || RawValue == other.RawValue);
    }

    public Half RawValue { get; }

    public override bool Equals(object? obj)
    {
        return obj is not null && (ReferenceEquals(this, obj) || (obj is CborHalfPrecisionFloat otherHalfPrecisionFloat && Equals(otherHalfPrecisionFloat)));
    }

    public override int GetHashCode()
    {
        return HashCode.Combine((int) ActualType, RawValue);
    }

    public static bool operator ==(CborHalfPrecisionFloat? left, CborHalfPrecisionFloat? right)
    {
        return Equals(left, right);
    }

    public static bool operator !=(CborHalfPrecisionFloat? left, CborHalfPrecisionFloat? right)
    {
        return !Equals(left, right);
    }
}